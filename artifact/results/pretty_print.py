import os
import sys
import json
import datetime

if __name__ == '__main__':
    path = sys.argv[1]
    assert os.path.exists(path)

    chain_verified_cnt = 0
    chain_gen_cnt = 0
    total_chain_build_cnt = 0
    total_chain_build_time = 0
    total_find_gadget_time = 0
    total_find_gadget_cnt = 0
    total_init_time = 0
    total_init_cnt = 0
    timeout_cnt = 0
    total = 0
    total_time = 0
    total_gadget = 0
    gadget_n = 0
    total_chain_search_time = 0
    total_chain_search_cnt = 0
    total_chain_cnt = 0
    total_chain_len = 0

    sgc_total_chains = 0
    sgc_total_verified_chains = 0

    with open(path) as f:
        for line in f:
            data = json.loads(line)
            total += 1
            entry_time = 0
            if 'chain_verify' in data and data['chain_verify'] is True:
                chain_verified_cnt += 1
            if 'chain_verify_known_payload_addr' in data:
                entries = data['chain_verify_known_payload_addr']
                if any(x[0] is True for x in entries):
                    chain_verified_cnt += 1
                sgc_total_chains += len(entries)
                sgc_total_verified_chains += len([x for x in entries if x[0] is True])
            if 'chain_build' in data and data['chain_build'] is True:
                chain_gen_cnt += 1
            if 'chain_bytes' in data and data['chain_bytes']:
                total_chain_cnt += 1
                total_chain_len += len(data['chain_bytes'])//2 # bytes are in hex
            if 'find_gadgets_time' in data and data['find_gadgets_time'] is not None:
                total_find_gadget_cnt += 1
                total_find_gadget_time += data['find_gadgets_time']
                entry_time += data['find_gadgets_time']
            if 'builder_optimize_time' in data and data['builder_optimize_time'] is not None:
                total_init_cnt += 1
                total_init_time += data['builder_optimize_time']
                entry_time += data['builder_optimize_time']
            if 'chain_build_time' in data and data['chain_build_time'] is not None:
                total_chain_build_cnt += 1
                total_chain_build_time += data['chain_build_time']
                entry_time += data['chain_build_time']
            if 'chain_search_time' in data and data['chain_search_time'] is not None:
                total_chain_search_cnt += 1
                total_chain_search_time += data['chain_search_time']
            if 'timeout' in data and data['timeout'] is True:
                timeout_cnt += 1

            if 'gadget_cnt' in data and data['gadget_cnt'] is not None:
                total_gadget += data['gadget_cnt']
                gadget_n += 1

            # calculate the time
            if 'timeout' in data and data['timeout'] is True:
                total_time += 30*60
                if 'find_gadgets' not in data or not data['find_gadgets']:
                    total_find_gadget_cnt += 1
                    total_find_gadget_time += 30*60
                elif 'builder_optimize' in data and not data['builder_optimize']:
                    total_init_cnt += 1
                    total_init_time += 30*60
                elif not data['chain_build']:
                    total_chain_build_cnt += 1
                    total_chain_build_time += 30*60
                else:
                    pass
            else:
                total_time += entry_time

            if not ('chain_verify' in data and data['chain_verify'] is True) and ('chain_build' in data and data['chain_build'] is True):
                print(line)


        print("success:", chain_verified_cnt)
        print("generated:", chain_gen_cnt)
        if sgc_total_chains or sgc_total_verified_chains:
            print("false posistives", ((sgc_total_chains-sgc_total_verified_chains)/sgc_total_chains)* 100, '%')
        elif chain_gen_cnt:
            print("false posistives", (chain_gen_cnt-chain_verified_cnt)/chain_gen_cnt * 100, '%')
        else:
            print("false posistives: -")
        print("gadget finding time:", total_find_gadget_time/total_find_gadget_cnt)
        if total_init_cnt:
            print("init time:", total_init_time/total_init_cnt)
        else:
            print("init time: - ")
        if total_chain_search_cnt:
            print("chain search time:", total_chain_search_time/total_chain_search_cnt)

        print("time-to-chain:", total_chain_build_time/total_chain_build_cnt)
        print("timeout rate:", timeout_cnt/total*100, '%')
        #print("total_time:", str(datetime.timedelta(seconds=total_time)))
        print("total_time:", total_time/60/60, 'h')
        print("avg time:", total_time/total)

        print("avg_chain_len:", total_chain_len/total_chain_cnt)
        print("gadget_cnt", total_gadget/gadget_n)
