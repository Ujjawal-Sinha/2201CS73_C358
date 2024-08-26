from scapy.all import *
import socket
import time

# Objective 2: Scapy-based Tracert Utility

# 1. Basic Functionality
# Function to perform a trace route to the destination IP
def scapy_tracert(destination, max_ttl=30, packet_size=64, timeout=2, ping_per_hop=3, delay_between_pings=0.5):
    # Error Handling for Invalid Destination IP (Task 3: Error Handling)
    try:
        ip = socket.gethostbyname(destination)
    except socket.error:
        print("Invalid IP address.")
        return
    
    # Error Handling for Invalid Max TTL Value (Task 3: Error Handling)
    if not (1 <= max_ttl <= 255):
        raise ValueError("Invalid TTL value. Must be between 1 and 255.")
    
    # Error Handling for Invalid Packet Size (Task 3: Error Handling)
    if packet_size < 0:
        raise ValueError("Packet size must be a positive integer.")

    output = ""
    
    # Print the initial message indicating the start of the trace route
    print(f"Tracing route to {destination} [{ip}] with a maximum of {max_ttl} hops:\n")
    output += f"Tracing route to {destination} [{ip}] with a maximum of {max_ttl} hops:\n\n"
    
    # Loop over each TTL value from 1 to max_ttl (Task 1: Basic Functionality)
    for ttl in range(1, max_ttl + 1):
        rtt_sum = 0
        rtt_count = 0
        loss_count = 0
        hop_ip = None
        
        # Send multiple pings for each hop (Task 2: Additional Features)
        for _ in range(ping_per_hop):
            pkt = IP(dst=ip, ttl=ttl) / ICMP() / Raw(b'X' * packet_size)
            start_time = time.time()
            reply = sr1(pkt, verbose=0, timeout=timeout)
            end_time = time.time()
            
            if reply is None:
                # Handling request timeouts
                print(f"Hop {ttl}: Request timed out.")
                output += f"Hop {ttl}: Request timed out.\n"
                loss_count += 1
            else:
                hop_ip = reply.src
                rtt = (end_time - start_time) * 1000  # Convert to milliseconds
                rtt_sum += rtt
                rtt_count += 1
                
                # Print each hop's IP and RTT (Task 4: Output Formatting)
                print(f"Hop {ttl}: {hop_ip} | RTT: {rtt:.2f} ms")
                output += f"Hop {ttl}: {hop_ip} | RTT: {rtt:.2f} ms\n"
            
            time.sleep(delay_between_pings)
        
        if rtt_count > 0:
            # Calculate average RTT and packet loss percentage (Task 4: Output Formatting)
            avg_rtt = rtt_sum / rtt_count
            loss_percentage = (loss_count / ping_per_hop) * 100
            print(f"Average RTT: {avg_rtt:.2f} ms | Packet loss: {loss_percentage:.2f}%\n")
            output += f"Average RTT: {avg_rtt:.2f} ms | Packet loss: {loss_percentage:.2f}%\n\n"
        else:
            print(f"Packet loss: 100.00%\n")
            output += "Packet loss: 100.00%\n\n"
        
        if hop_ip == ip:
            # Stop if the destination is reached
            print("Reached the destination.\n")
            output += "Reached the destination.\n"
            break

    # Save output to a file (Task 2: Additional Features)
    with open("tracert_output.txt", "w") as file:
        file.write(output)

# Example usage (Task 1: Basic Functionality)
scapy_tracert("google.com", max_ttl=20, ping_per_hop=3, delay_between_pings=0.5)
