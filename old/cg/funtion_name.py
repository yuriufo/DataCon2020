import re

def get_funtion(fp):
    with open(fp, 'rb') as f:
        data = f.readlines()

    color_line_pre = 0
    while b'node' != data[color_line_pre][:4]:
        color_line_pre += 1

    node_line_pre = color_line_pre
    nodes = {}
    pat1 = b'node: { title: \"(.*)\" label: \"(.*)\" color: (.*) textcolor: (.*) bordercolor: (.*) }'
    pat2 = b'node: { title: \"(.*)\" label: \"(.*)\" color: (.*) bordercolor: (.*) }'
    while b'// node' != data[node_line_pre][:7]:
        so1 = re.search(pat1, data[node_line_pre], re.I)
        so2 = re.search(pat2, data[node_line_pre], re.I)
        if so1 is not None:
            nodes[so1.group(1)] = [so1.group(2), so1.group(3), so1.group(4), so1.group(5)]
        elif so2 is not None:
            nodes[so2.group(1)] = [so2.group(2), so2.group(3), so2.group(4)]
        else:
            print(data[node_line_pre])
        node_line_pre += 1

    edge_line_pre = node_line_pre
    weight = {k: 0 for k in list(nodes.keys())}
    source = {k: [] for k in list(nodes.keys())}
    pat3 = b'edge: { sourcename: \"(.*)\" targetname: \"(.*)\" }'
    while 125 != data[edge_line_pre][0]:
        so3 = re.search(pat3, data[edge_line_pre], re.I)
        if so3 is not None:
            weight[so3.group(1)] += 1
            source[so3.group(1)].append(so3.group(2))
        edge_line_pre += 1

    weight_list = sorted(weight.items(), key=lambda d: d[1], reverse=True)
    function = [(nodes[t][0], i, n)  for i, (t, n) in enumerate(weight_list)]
    # node_list = [node for node, _ in weight_list]
    # if len(weight_list) == 200:
    #     new_node = []
    #     new_edge = []
    #     for i, (node, _) in enumerate(weight_list):
    #         node_info = nodes[node]
    #         if len(node_info) == 4:
    #             new_node.append(b'node: { title: "' + str(i).encode('utf-8') + b'" label: "' + node_info[0] + b'" color: ' + node_info[1] + b' textcolor: ' + node_info[2] + b' bordercolor: ' + node_info[3] + b' }\n')
    #         else:
    #             new_node.append(b'node: { title: "' + str(i).encode('utf-8') + b'" label: "' + node_info[0] + b'" color: ' + node_info[1] + b' bordercolor: ' + node_info[2] + b' }\n')
    #         for target in source[node]:
    #             if target in node_list:
    #                 new_edge.append(b'edge: { sourcename: "' + node + b'" targetname: "' + target + b'" }\n')
    # new_data = data[0:color_line_pre] + new_node + new_edge + [b'}']
    # with open(fp, 'wb') as f:
    #     f.writelines(new_data)

    return function
