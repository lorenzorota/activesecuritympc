import os

def substitute_variables(input_file, output_file, substitutions):
    with open(input_file, 'r') as file:
        content = file.read()

    for variable, value in substitutions.items():
        placeholder = f'{{{variable}}}'
        content = content.replace(placeholder, str(value))

    with open(output_file, 'w') as file:
        file.write(content)

# Create folders if they are missing
if not os.path.exists('zk_statements'):
    os.makedirs('zk_statements')
if not os.path.exists('decompositions'):
    os.makedirs('decompositions')

zk_statements_protocol_input = 'zk_statements_template_protocol.py.txt'
decomposition_protocol_input = 'decomposition_template_protocol.py.txt'
additive_input = 'decomposition_template_additive.py.txt'

for i in range(3, 101):
    INPUT = i
    INPUT2 = 2*INPUT
    INPUT3 = INPUT-1

    substitutions = {
        'INPUT': INPUT,
        'INPUT2': INPUT2,
        'INPUT3': INPUT3,
    }

    # Output files 
    zk_statements_protocol_output = 'zk_statements/protocol_{}p.py'.format(INPUT)
    decomposition_protocol_output = 'decompositions/protocol_{}p.py'.format(INPUT)
    additive_output = 'decompositions/additive_{}p.py'.format(INPUT)

    # Perform substitutions
    substitute_variables(zk_statements_protocol_input, zk_statements_protocol_output, substitutions)
    substitute_variables(decomposition_protocol_input, decomposition_protocol_output, substitutions)
    substitute_variables(additive_input, additive_output, substitutions)