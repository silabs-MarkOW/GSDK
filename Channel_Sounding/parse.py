import sys

filename = sys.argv[1]

fh = open(filename,'r')
text = fh.read()
fh.close()

lines = text.split('\n')
for line in lines :
    tokens = line.split()
    if len(tokens) < 2 : continue
    if 'Step' != tokens[0] : continue
    if 'data:' != tokens[1] : continue
    length = len(tokens[2])
    if 1 & length : raise ErrorRuntime('odd length')
    octets = []
    for i in range(length >> 1) :
        octets.append(int(tokens[2][i<<1:][:2],16))
    print(octets)
    while len(octets) > 3 :
        remainder = octets[3:]
        step_mode = octets[0]
        step_channel = octets[1]
        step_data_length = octets[2]
        if step_data_length > len(remainder) :
            raise RuntimeError('step_data_length:%d > len(remainder):%d'%(step_data_length, len(remainder)))
        octets = remainder[step_data_length:]
        print('mode:%d, channel:%d, length:%d'%(step_mode,step_channel,step_data_length),remainder)
    if len(octets) :
        raise RuntimeError(octets)
