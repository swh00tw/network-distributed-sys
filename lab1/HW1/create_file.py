import sys


def create_file(n):
    with open(f'large_test_{n}.txt', 'w') as file:
        for i in range(n):
            line = ''
            for _ in range(0, 128):
                line += f'packet{i:02d}'

            # erase last character
            line = line[:1023]
            line += '\n'
            file.write(line)
        file.write('END.')


if __name__ == '__main__':
    # take first args as n
    n = int(sys.argv[1])
    create_file(n)
