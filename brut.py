import bcrypt
import time
from multiprocessing import Process, Queue, cpu_count, Manager

def find_password_chunk(target_hash_str, start, end, result_queue):
    target_hash_bytes = target_hash_str.encode('utf-8')
    checked_count = 0  
    total_passes = end - start + 1 
    
    for number in range(start, end+1):
        password_str = f"{number:06d}" 
        password_bytes = password_str.encode('utf-8')

        if bcrypt.checkpw(password_bytes, target_hash_bytes):
            result_queue.put((True, password_str))  
            return

        checked_count += 1
        print(f"\r{checked_count / total_passes * 100:.2f}% ", end='', flush=True)
    
    result_queue.put((False, None)) 

def remove_hash_from_file(target_hash, input_file):
    temp_lines = []
    with open(input_file, 'r', encoding='utf-8') as infile:
        for line in infile:
            if line.strip() != target_hash:
                temp_lines.append(line)
    
    with open(input_file, 'w', encoding='utf-8') as outfile:
        outfile.writelines(temp_lines)

def main():
    start_time = time.time()
    hash_input_file = r"tocheck.txt"
    output_file = r"bo.txt"
    with open(hash_input_file, 'r', encoding='utf-8') as infile:
        hashes = infile.read().splitlines()
    
    with open(output_file, 'w', encoding='utf-8') as outfile:
        for target_hash in hashes[:]: 
            print(f"{target_hash}")
            
            num_processes = cpu_count()
            print(f"{num_processes}")

            manager = Manager()
            result_queue = manager.Queue()
            
            total_range = 900000 
            chunk_size = total_range // num_processes

            processes = []
            for i in range(num_processes):
                start = 100000 + i * chunk_size
                end = start + chunk_size - 1
                               
                if i == num_processes - 1:
                    end = 999999
                
                p = Process(target=find_password_chunk, args=(target_hash, start, end, result_queue))
                processes.append(p)
                p.start()
          
            found_password = None
            for _ in range(len(processes)):
                success, password = result_queue.get()
                if success:
                    found_password = password
                    break
            
            for p in processes:
                p.terminate()
                p.join()
            
            if found_password:
                outfile.write(f"{target_hash}:{found_password}\n")  
                print(f"{target_hash}: {found_password}")
                remove_hash_from_file(target_hash, hash_input_file)
            else:
                print(f"{target_hash}.")
    
    end_time = time.time()
    elapsed_time = end_time - start_time
    print("\n:", round(elapsed_time, 2), "??????.")

if __name__ == "__main__":
    print("""
         ____  ____  _   _ _____         
        | __ )|  _ \| | | |_   _|        
 _____  |  _ \| |_) | | | | | |    _____ 
|_____| | |_) |  _ <| |_| | | |   |_____|
        |____/|_| \_\\___/  |_|          

Telegram - @kaliceo
Github - github.com/Levako098


    """)
    main()