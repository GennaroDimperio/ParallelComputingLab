import re
import matplotlib.pyplot as plt
import time
from multiprocessing import Pool
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

def categorize_log_entry(log_entry):
    ip_match = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", log_entry)
    ip = ip_match.group(0) if ip_match else None
    
    if "Connection closed" in log_entry and "[preauth]" in log_entry:
        return "Connection closed [preauth]", ip
    elif ("Invalid user" in log_entry or "input_userauth_request" in log_entry) and "[preauth]" in log_entry:
        return "Invalid user [preauth]", ip
    elif ("authentication failure" in log_entry or "Failed password" in log_entry) and "[preauth]" in log_entry:
        return "Authentication failure [preauth]", ip
    elif "Received disconnect" in log_entry and "[preauth]" in log_entry:
        return "Disconnect [preauth]", ip
    elif "reverse mapping" in log_entry and "[preauth]" in log_entry:
        return "Reverse mapping failed [preauth]", ip
    elif "not map back to the address" in log_entry:
        return "Suspicious Mapping", ip
    elif "Connection closed" in log_entry:
        return "Connection closed", ip
    elif "Invalid user" in log_entry or "input_userauth_request" in log_entry:
        return "Invalid user", ip
    elif "authentication failure" in log_entry or "Failed password" in log_entry:
        return "Authentication failure", ip
    elif "Received disconnect" in log_entry:
        return "Disconnect", ip
    elif re.search(r"Failed [0-9]+ attempts", log_entry):
        return "Suspicious activity", ip
    elif "reverse mapping" in log_entry:
        return "Reverse mapping failed", ip
    else:
        return "Unknown", ip

def process_log_sequential(log_file_path):
    ip_category_counts_S = defaultdict(set)
    intrusion_signs = []
    
    with open(log_file_path, "r") as log_file:
        for line in log_file:
            log_entry = line.strip()
            category, ip = categorize_log_entry(log_entry)
            if category != "Unknown":
                intrusion_signs.append(category)
                ip_category_counts_S[ip].add(category)

    with open(ip_path, "w") as output_file:
        for ip, categories in ip_category_counts_S.items():
            if len(categories) >= 2 and ip:
                output_file.write(f"{ip}: {len(categories)} categories: {categories}\n")

    category_counts = defaultdict(int)
    for category in intrusion_signs:
        category_counts[category] += 1

    sorted_categories = sorted(category_counts, key=category_counts.get, reverse=True)
    sorted_sizes = [category_counts[category] for category in sorted_categories]

    plt.figure(figsize=(8, 6))
    plt.bar(sorted_categories, sorted_sizes)
    plt.xticks(rotation=45, ha='right')
    plt.xlabel('Category')
    plt.ylabel('Frequency')
    plt.title('Categorized Log Entries SEQ')
    plt.show()

def process_chunk(chunk):
    local_ip_category_counts = defaultdict(set)
    local_intrusion_signsP = []
    for log_entry in chunk:
        category, ip = categorize_log_entry(log_entry)
        if category != "Unknown":
            local_intrusion_signsP.append(category)
            local_ip_category_counts[ip].add(category)
    return local_ip_category_counts, local_intrusion_signsP

def merge_results(results):
    merged_ip_counts = defaultdict(set)
    merged_intrusion_signs = []

    for ip_counts, intrusion in results:
        merged_intrusion_signs.extend(intrusion)
        for ip, categories in ip_counts.items():
            merged_ip_counts[ip].update(categories)

    return merged_ip_counts, merged_intrusion_signs

def write_ip_txt(ip, categories):
    with open(ip_path2, "a") as output_file:
        if len(categories) >= 2 and ip:
            output_file.write(f"{ip}: {len(categories)} categories: {categories}\n")

def process_log_parallel(log_file_path, num_processes):
    with open(log_file_path, "r") as log_file:
        lines = log_file.readlines()

    chunk_size = (len(lines) + num_processes - 1) // num_processes
    chunks = [lines[i:i + chunk_size] for i in range(0, len(lines), chunk_size)]

    with Pool(processes=num_processes) as pool:
        results = pool.map(process_chunk, chunks)
    
    ip_category_countsP, intrusion_signs = merge_results(results)

    with ThreadPoolExecutor(max_workers=num_processes) as executor:
        futures = [executor.submit(write_ip_txt, ip, categories) for ip, categories in ip_category_countsP.items()]

    for future in futures:
        future.result()

    category_counts = defaultdict(int)
    for category in intrusion_signs:
        category_counts[category] += 1

    sorted_categories = sorted(category_counts, key=category_counts.get, reverse=True)
    sorted_sizes = [category_counts[category] for category in sorted_categories]

    plt.figure(figsize=(8, 6))
    plt.bar(sorted_categories, sorted_sizes)
    plt.xticks(rotation=45, ha='right')
    plt.xlabel('Category')
    plt.ylabel('Frequency')
    plt.title('Categorized Log Entries PAR')
    plt.show()

if __name__ == '__main__':
    ip_path = "C:\\Users\\Empir\\Desktop\\ip.txt"
    ip_path2 = "C:\\Users\\Empir\\Desktop\\ip2.txt"
    log_file_path = "C:\\Users\\Empir\\Desktop\\SSH2.log"
    # Sequential Processing
    start_time = time.time()
    process_log_sequential(log_file_path)
    end_time = time.time()
    execution_timeS = end_time - start_time
    print("Sequential execution time: {:.2f} seconds".format(execution_timeS))
    # Parallel Processing
    num_processes = 8
    start_time = time.time()
    process_log_parallel(log_file_path, num_processes)
    end_time = time.time()
    execution_timeP = end_time - start_time
    print("Parallel execution time: {:.2f} seconds with {} processors".format(execution_timeP, num_processes))
    speedup = execution_timeS / execution_timeP
    print("Speedup: {:.2f}".format(speedup))
