#!/home/noccsync/nocc/bin/python

import pexpect
import re
import itertools
import socket
import sys
import argparse
from cgi import escape
from copy import deepcopy
import ipaddress
import copy

#Defining a custom data structure to store the route data
class Node:
    def __init__(self, value, parent=None):
        self.parent=parent
        self.children=[]
        self.value=str(value)
    
    def is_child(self, other_node):
        for child in self.children:
            if child.value == other_node.value:
                return True
        else:
            return False
                
        #Helpful to define a "in" magic function someday
#        if other_node in self.children:
#            return True
#        else:
#            return False
        
    def add_child(self, child_value):
        #Check if we are adding a Node or a string
        if isinstance(child_value, Node):
            self.add_child_node(child_value)
        else:
            child_node = Node(child_value, parent=self)
            self.add_child_node(child_node)
                   
    def add_child_node(self, node):
        #Add node if its not there
        if not node in self.children:
            new_node = deepcopy(node)
            self.children.append(new_node)
            return 0
        #Otherwise return an error
        else:
            return -1

    def get_child_node(self, value):
        for child in self.children:
            if value == child.value:
                return child
        else:
            return None

    def merge(self, node, dummy=True):
        #dummy variable is to keep track of the leaves
        if self.is_child(node):
            self_child_pointer = self.get_child_node(node.get_value())
            if not self_child_pointer.children or not node.children:
                if not self_child_pointer.get_child_node('*'):
                    self_child_pointer.add_child('*')
            for child in node.children:
                self_child_pointer.merge(child, dummy=False)
        else:
            self.add_child_node(node)
    
    def get_value(self):
        return self.value
        
    def get_children(self):
        return [child for child in self.children]
        
    def get_value_len(self):
        return len(self.value)
        
    def is_first_child(self, child):
        return self.children[0] == child
                
    def is_last_child(self, child):
        return self.children[-1] == child

    def get_tree(self, indent=''):
        treelet = self.value 
        for child in self.children:
            if self.is_first_child(child):
                node_indent = '' #No indentation needed for first child - it will continue along with the parent line
                node_sep = '-+-' #Separator for the first child
                #prepping up for its children - it needs the node indent
                #If we have only one child, the brach need not be shown
                child_extender = len(self.get_value()) * ' ' #the len is to get the node_ident of the parent into the children
                first_child_indent = indent
                if len(self.children) == 1:
                    child_extender += '   '  #Accomodating the node_sep with empty sapces
                #If we have mode than one childrem, the vertical extension branch needs to be drawn (Accomodating the node_sep)
                else:
                    child_extender += ' | '
            elif self.is_last_child(child):
                node_indent = indent + len(self.value) * ' ' #Need to indent the non-first child by parent length
                node_sep = ' `-'   #A different separator for last child
                first_child_indent = ''
                child_extender = '   ' #last child - does not need any branches to be carried over
            else:
                first_child_indent = ''                
                node_indent = indent + len(self.value) * ' ' #Need to indent the non-first child by parent length
                node_sep = ' |-'  #A different separator for intermediate children
                child_extender = ' | '                 #If we have mode than one childrem, the vertical extension branch needs to be drawn (Accomodating the node_sep)
            
            #All tree connectors and separators should be defined by now (plotting the children tree)
            #indent -> The indent from the curent tree is passed to the children
            #node_indent -> The indent needed for the children due to the current node (first child - nothing, others - the len of the current node
            #child_extender -> For children of the child 
            treelet += node_indent + node_sep + child.get_tree(indent = first_child_indent+node_indent+child_extender)

        if not self.children:
            treelet += '\n'
        return treelet


def create_dot_graph(network_key, route_l, asn_d):
#Writing out a dot file for graphing
    graph='\n/*The below code is a dot file, which can be used to plot a hierarchical graph.\nUse the code at https://graphs.grevian.org/graph to plot it - layout method = dot.*/\n'
    graph+='digraph route_graph {{ label = "{}"\nlabelloc=top\nsplines=ortho\nnode [shape="rectangle"]\n'.format(network_key)
            
    edges=''
    new_asn = set()
    for i in route_l:
        prev=''
        path=[]
        for j in i:
            if j == prev:
                out = "_" + j
            else:
                out = j
                prev = j
            path.append(out)
        new_asn.update(path)
        edges += "->".join(path)
        edges += '\n'
    graph += edges

    nodes = ''

    for i in new_asn:
        nodes += '{} [ label=<{}<BR /><FONT POINT-SIZE="10">{}</FONT>> ]\n'.format(i, i.replace("_",''), escape(asn_d[i.replace("_",'')]['asname']))
    graph += nodes
    graph += "}"
    return graph


class RouteView(object):
    hostname = ''
    access_prompt = ''
    access_user = ''
    access_password = ''
    cli_prompt = ''

    def __init__(self,
                 hostname,
                 access_prompt,
                 access_user,
                 access_password,
                 cli_prompt):
        self.hostname = hostname
        self.access_prompt = access_prompt
        self.access_user = access_user
        self.access_password = access_password
        self.cli_prompt = cli_prompt

    def open(self):
        self.child = pexpect.spawn('telnet {}'.format(self.hostname))
        self.child.expect(self.access_prompt)
        self.child.sendline(self.access_user)
        self.child.expect(self.cli_prompt)
        self.child.send("terminal length 0\r")
        self.child.expect(self.cli_prompt)
        
    def close(self):
        self.child.close()

    def send_command(self, command):
        if self.child.isalive():
            self.child.sendline(command)
            self.child.expect(self.cli_prompt)
            return self.child.before
        else:
            return 127

    def show_ip_bgp(self, ipaddr, version=4):
        if version==4:
            #IPv4 has only one step process
            command = "show ip bgp {}".format(ipaddr)
        else:
            #IPv6 has 2 step process
            command = "show ipv6 route {}".format(ipaddr)
            result = self.send_command(command)
            v6_block = result.decode('utf-8').split('\r\n')[1].split(' ')[-1]
            command = "show bgp ipv6 unicast {}".format(v6_block)
        result = self.send_command(command)
        return result

    def parse_ip_bgp(self, result):
        result_l = result.decode('utf-8').split('\r\n')
        if 'Network not in table' in result_l[1]:
            return None, None
        network_re = re.compile('BGP routing table entry for (.*),')
        network = network_re.match(result_l[1]).groups()[0]
        route_l = []
        start = 4
        for routes in result_l[start:]:
            if routes.strip().startswith('Refresh Epoch'):
                route_l.append(result_l[start+1].split(',')[0].strip().split())
            start += 1
        return network, route_l


def parse_args():
    parser = argparse.ArgumentParser(description="""Script fetches the BGP route information for a 
network or for ip addresses and gives the ASN names for the ASnumbers""")

    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument('-ip', '--ip', dest='ip', type=str, nargs="+", help="Space separated IPs/Netblocks")

    parser.add_argument('-n', '--hop-count', dest='hops', type=int, help='Count of BGP hops to be displayed', required=True)

    parser.add_argument('--graph', dest='graph', action='store_true', help='Provides a dot file that can be used to create a graph')
    parser.add_argument('--ascii_tree', dest='ascii_tree', action='store_true', help="creates an ascii tree of the routes")
    
    args = parser.parse_args()

    # If no options are provided, print the help
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(-1)

    return args

def get_asn_data(asn_set):
    cy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cy.connect(("whois.cymru.com", 43))
    query = 'begin\nverbose\n' + 'AS' + '\nAS'.join(asn_set) + '\nend\n'
    #Python 3 needs a byte object passed
    if sys.version_info.major == 3:
        query = query.encode('utf-8')
    cy.sendall(query)
    response = ''
    while True:
        r = cy.recv(10)
        #Result will be a byte, converting it into string
        if sys.version_info.major == 3:
            r = r.decode()
        if r and r != '':
            response += r
        else:
            break
    cy.close()

    labels = ['asnum', 'country', 'reg', 'date', 'asname']
    as_dict = {}
    for line in response.split('\n'):
        if line == '' or line.startswith('Bulk'):
            continue
        info = [word.strip() for word in line.split('|')]
        as_dict[info[0]] = dict(zip(labels, info))
    return as_dict
    
def print_hop_info(route_l, asn_d, hop_no):
    route_d = {}
    for route in route_l:
        for i in range(0, min(hop_no, len(route))):
            if not route_d.get(i):
                route_d[i] = set()
            route_d[i].add(route[i])
    for k, v in route_d.items():
        #printing data for each hop
        print("Hop number: {}".format(k))
        print("--------")
        #iterating through each ASN in the hop set
        for asn in v:
            print("\tAS{}: {}".format(asn, asn_d[asn]['asname']))
        print("--------")

def draw_ascii_tree(network_key, route_l):
    route_nodes = []
    for route in route_l:
        #the BGP source is our root
        r_n = Node(route[0])
        #pointer to add children to each BGP AS addition
        pointer = r_n
        for asnum in route[1:]:
            pointer.add_child(asnum)
            pointer = pointer.get_child_node(asnum)
        route_nodes.append(r_n)
    #We will use the ip_network as the root node
    root_node=Node(network_key)
    for route in route_nodes:
        root_node.merge(route)
    return root_node.get_tree()

def get_route_d(ip):
    #Sanitize IP address and get it's version
    try:
        ip_o = ipaddress.ip_address(ip)
    except:
        return None, None
    version = ip_o.version
    #Return empty if IP address is not global IP
    if not ip_o.is_global:
        return None, None

    #Create a Route views connection object
    rviews_o = RouteView(hostname="route-views.routeviews.org",
                      access_prompt="Username:",
                      access_user="rviews",
                      access_password=None,
                      cli_prompt="route-views>")

    result_l = []
    route_d = {}
    #Open the connection, run the command, close the connection
    rviews_o.open()
    result = rviews_o.show_ip_bgp(ip_o.exploded, version=version)
    rviews_o.close()
    network, route_l = rviews_o.parse_ip_bgp(result)

    if not network:
        return ip, None

    #The data from BGP has source at the end
    #Reversing each route, so we will have source at the beginning
    for route in route_l:
        route.reverse()
        
    return network, route_l

if __name__ == '__main__':
    opts = parse_args()
    result_l = []
    route_d = {}
    #Creating a set since there will be a lot of AS repetititions
    asn_set = set()
    #Lots of repetitive code here, got to clean up some day
    if opts.ip:
        for ip_item in opts.ip:
            network, route_l = get_route_d(ip_item)
            route_d[network] = route_l
            if not route_l:
                print("No route found for {}".format(ip_item))
                continue

            #Bundling up the ASNs 
            asn_set.update([asn for asn in itertools.chain(*route_d[network])])

        #Now making a query to whois.cymru in one TCP request
        asn_d = get_asn_data(asn_set)
        for network_key in route_d.keys():
            #The code for writing out the ASnumber in each hop
            print("****\nBGP info for network: {}".format(network_key))
            if not route_d[network_key]:
                print("No route found for {}".format(ip_item))
                continue

            print_hop_info(route_d[network_key], asn_d, opts.hops)

            #To plot the graph
            if opts.graph and route_l != []:
                graph = create_dot_graph(network_key, route_l, asn_d)
                print(graph)

            #To draw the ascii tree
            if opts.ascii_tree and route_l != []:
                print("===ASCII tree of the routing table")
                tree = draw_ascii_tree(network_key, route_d[network_key])
                print(tree)
    


    
