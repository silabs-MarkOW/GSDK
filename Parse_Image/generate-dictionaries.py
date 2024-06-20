import argparse

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='set or show application version number')
    parser.add_argument('-i', '--interface', help='btl_interface.h')

    args = parser.parse_args()
    fh = open(args.interface,'r')
    text = fh.read()
    fh.close()

    lines = text.split('\n')
    matches = []
    for line in lines :
        if 0 == len(line) : continue
        tokens = line.split()
        if len(tokens) < 3 : continue
        if '#define' == tokens[0] and 0 == tokens[1].find('BOOTLOADER_CAPABILITY_') :
            matches.append('%s:"%s"'%(' '.join(tokens[2:]), tokens[1][22:]))
    print('capabilities = { %s }'%(', '.join(matches)))
