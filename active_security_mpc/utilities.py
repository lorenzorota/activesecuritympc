import os

def success_message(final):
    success_msg = "MPC successful. Final result: {}".format(final)
    msg = "\n+{}+\n".format((len(success_msg)+2)*'-')
    msg += "| {} |\n".format(success_msg)
    msg += "+{}+\n".format((len(success_msg)+2)*'-')    
    return msg

def error_message(trace):
    error_msg = "MPC unsuccessful. Trace: {}".format(trace)
    msg = "\n+{}+\n".format((len(error_msg)+2)*'-')
    msg += "| {} |\n".format(error_msg)
    msg += "+{}+\n".format((len(error_msg)+2)*'-')
    return msg

def commitments_info(commitments):
    depth = lambda L: isinstance(L, list) and max(map(depth, L))+1
    msg = ""
    if depth(commitments) == 2:
        for idx, commit in enumerate(commitments):
            msg += "commitment {}: {}\n".format(idx, commit)
        return msg
    elif depth(commitments) == 3:
        for idx1, party in enumerate(commitments):
            msg += "party {}:\n".format(idx1)
            for idx2, commit in enumerate(party):
                 msg += "\t commitment {}: {}\n".format(idx2, commit)
        return msg

def shares_info(shares):
    msg = ""
    for idx, share in enumerate(shares):
        msg += "share {}: {}\n".format(idx, share)
    return msg

def blinding_factors_info(blinding_factors):
    msg = ""
    for idx, factors in enumerate(unflatten_list(blinding_factors, 2)):
        msg += "blinding factors {}: {}\n".format(idx, factors)
    return msg

def flatten_list(lst):
    return [item for sublist in lst for item in sublist]

def unflatten_list(lst, sublist_length):
    return [lst[i:i+sublist_length] for i in range(0, len(lst), sublist_length)]

def get_dir_size(dir_path):
    total_size = 0
    folder_sizes = {}
    for dirpath, dirnames, filenames in os.walk(dir_path):
        folder_size = 0
        for file in filenames:
            file_path = os.path.join(dirpath, file)
            if not os.path.islink(file_path):
                size = os.path.getsize(file_path)
                folder_size += size
                total_size += size
        folder_sizes[dirpath.split('/')[-1]] = folder_size
    folder_sizes.pop(dir_path) # remove main folder as it stores no files, only directories
    return total_size, folder_sizes