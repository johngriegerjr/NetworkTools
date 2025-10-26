import tkinter as tk
from tkinter import ttk
import subprocess
import threading
import queue
import tempfile
import os
import socket

def main():
    window = tk.Tk()
    window.title("SNMP Tool")
    window.geometry("800x600")
    window.resizable(True, True)

    notebook = ttk.Notebook(window)
    notebook.pack(pady=10, padx=10, fill="both", expand=True)

    walk_tab = tk.Frame(notebook)
    notebook.add(walk_tab, text="SNMP Walk")

    trap_tab = tk.Frame(notebook)
    notebook.add(trap_tab, text="Trap Receiver")

    # SNMP Walk Tab
    top_frame = tk.Frame(walk_tab)
    top_frame.pack(pady=10, padx=10, fill="x")

    ip_label = tk.Label(top_frame, text="IP/Hostname:")
    ip_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
    ip_entry = tk.Entry(top_frame, width=30)
    ip_entry.grid(row=0, column=1, padx=5, pady=5)

    oid_label = tk.Label(top_frame, text="OID:")
    oid_label.grid(row=0, column=2, padx=5, pady=5, sticky="e")
    oid_entry = tk.Entry(top_frame, width=30)
    oid_entry.insert(0, "1.3.6.1")
    oid_entry.grid(row=0, column=3, padx=5, pady=5)

    version_label = tk.Label(top_frame, text="SNMP Version:")
    version_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
    versions = ["v1", "v2c", "v3"]
    version_var = tk.StringVar(value="v2c")
    version_menu = ttk.Combobox(top_frame, textvariable=version_var, values=versions, width=27)
    version_menu.grid(row=1, column=1, padx=5, pady=5)

    fields_frame = tk.Frame(walk_tab)
    fields_frame.pack(pady=10, padx=10, fill="x")

    entries = {}

    def update_fields(*args):
        for widget in fields_frame.winfo_children():
            widget.destroy()
        entries.clear()
        ver = version_var.get()
        row = 0
        if ver in ["v1", "v2c"]:
            comm_label = tk.Label(fields_frame, text="Community:")
            comm_label.grid(row=row, column=0, padx=5, pady=5, sticky="e")
            comm_entry = tk.Entry(fields_frame, width=30)
            comm_entry.insert(0, "public")
            comm_entry.grid(row=row, column=1, padx=5, pady=5)
            entries["community"] = comm_entry
        elif ver == "v3":
            user_label = tk.Label(fields_frame, text="Username:")
            user_label.grid(row=row, column=0, padx=5, pady=5, sticky="e")
            user_entry = tk.Entry(fields_frame, width=30)
            user_entry.grid(row=row, column=1, padx=5, pady=5)
            entries["username"] = user_entry
            row += 1

            auth_label = tk.Label(fields_frame, text="Auth Protocol:")
            auth_label.grid(row=row, column=0, padx=5, pady=5, sticky="e")
            auth_vars = ["None", "MD5", "SHA"]
            auth_var = tk.StringVar(value="None")
            auth_menu = ttk.Combobox(fields_frame, textvariable=auth_var, values=auth_vars, width=27)
            auth_menu.grid(row=row, column=1, padx=5, pady=5)
            entries["auth_proto"] = auth_var
            row += 1

            authpass_label = tk.Label(fields_frame, text="Auth Password:")
            authpass_label.grid(row=row, column=0, padx=5, pady=5, sticky="e")
            authpass_entry = tk.Entry(fields_frame, show="*", width=30)
            authpass_entry.grid(row=row, column=1, padx=5, pady=5)
            entries["auth_pass"] = authpass_entry
            row += 1

            priv_label = tk.Label(fields_frame, text="Priv Protocol:")
            priv_label.grid(row=row, column=0, padx=5, pady=5, sticky="e")
            priv_vars = ["None", "DES", "AES"]
            priv_var = tk.StringVar(value="None")
            priv_menu = ttk.Combobox(fields_frame, textvariable=priv_var, values=priv_vars, width=27)
            priv_menu.grid(row=row, column=1, padx=5, pady=5)
            entries["priv_proto"] = priv_var
            row += 1

            privpass_label = tk.Label(fields_frame, text="Priv Password:")
            privpass_label.grid(row=row, column=0, padx=5, pady=5, sticky="e")
            privpass_entry = tk.Entry(fields_frame, show="*", width=30)
            privpass_entry.grid(row=row, column=1, padx=5, pady=5)
            entries["priv_pass"] = privpass_entry

    version_var.trace("w", update_fields)
    update_fields()

    walk_buttons_frame = tk.Frame(walk_tab)
    walk_buttons_frame.pack(pady=10, padx=10)

    walk_run_button = tk.Button(walk_buttons_frame, text="Run")
    walk_run_button.grid(row=0, column=0, padx=5)
    walk_cancel_button = tk.Button(walk_buttons_frame, text="Cancel", state="disabled")
    walk_cancel_button.grid(row=0, column=1, padx=5)

    walk_log_frame = tk.Frame(walk_tab)
    walk_log_frame.pack(pady=10, padx=10, fill="both", expand=True)

    walk_scrollbar = tk.Scrollbar(walk_log_frame)
    walk_log_text = tk.Text(walk_log_frame, yscrollcommand=walk_scrollbar.set, wrap="word", height=10)
    walk_scrollbar.config(command=walk_log_text.yview)
    walk_log_text.pack(side="left", fill="both", expand=True)
    walk_scrollbar.pack(side="right", fill="y")

    # Trap Receiver Tab
    trap_top_frame = tk.Frame(trap_tab)
    trap_top_frame.pack(pady=10, padx=10, fill="x")

    port_label = tk.Label(trap_top_frame, text="Port:")
    port_label.grid(row=0, column=0, padx=5, pady=5, sticky="e")
    port_entry = tk.Entry(trap_top_frame, width=30)
    port_entry.insert(0, "10162")
    port_entry.grid(row=0, column=1, padx=5, pady=5)

    filter_label = tk.Label(trap_top_frame, text="Filter:")
    filter_label.grid(row=1, column=0, padx=5, pady=5, sticky="e")
    filter_entry = tk.Entry(trap_top_frame, width=30)
    filter_entry.grid(row=1, column=1, padx=5, pady=5)

    trap_buttons_frame = tk.Frame(trap_tab)
    trap_buttons_frame.pack(pady=10, padx=10)

    trap_start_button = tk.Button(trap_buttons_frame, text="Start")
    trap_start_button.grid(row=0, column=0, padx=5)
    trap_stop_button = tk.Button(trap_buttons_frame, text="Stop", state="disabled")
    trap_stop_button.grid(row=0, column=1, padx=5)

    trap_log_frame = tk.Frame(trap_tab)
    trap_log_frame.pack(pady=10, padx=10, fill="both", expand=True)

    trap_scrollbar = tk.Scrollbar(trap_log_frame)
    trap_log_text = tk.Text(trap_log_frame, yscrollcommand=trap_scrollbar.set, wrap="word", height=10)
    trap_scrollbar.config(command=trap_log_text.yview)
    trap_log_text.pack(side="left", fill="both", expand=True)
    trap_scrollbar.pack(side="right", fill="y")

    # Variables for Walk
    process_walk = [None]
    running_walk = [False]
    output_queue_walk = queue.Queue()

    def check_queue_walk():
        try:
            while True:
                line = output_queue_walk.get_nowait()
                walk_log_text.insert(tk.END, line)
                walk_log_text.see(tk.END)
        except queue.Empty:
            pass
        if running_walk[0]:
            window.after(100, check_queue_walk)
        else:
            walk_cancel_button.config(state="disabled")
            walk_run_button.config(state="normal")

    def execute_cmd_walk(cmd):
        try:
            process_walk[0] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8', errors='replace', bufsize=1)
            for line in iter(process_walk[0].stdout.readline, ''):
                output_queue_walk.put(line)
            process_walk[0].wait()
            if process_walk[0].returncode != 0:
                output_queue_walk.put(f"\nProcess exited with code {process_walk[0].returncode}\n")
        except Exception as e:
            output_queue_walk.put(f"\nError: {str(e)}\n")
        finally:
            running_walk[0] = False
            output_queue_walk.put("\nFinished\n")
            process_walk[0] = None

    def run_snmp():
        if running_walk[0]:
            return
        walk_log_text.delete(1.0, tk.END)
        ip = ip_entry.get().strip()
        if not ip:
            walk_log_text.insert(tk.END, "Please enter IP/Hostname\n")
            return
        oid = oid_entry.get().strip()
        if not oid:
            walk_log_text.insert(tk.END, "Please enter OID\n")
            return
        ver = version_var.get()
        cmd = ["snmpwalk"]
        if ver == "v1":
            cmd.append("-v1")
        elif ver == "v2c":
            cmd.append("-v2c")
        elif ver == "v3":
            cmd.append("-v3")
        if ver in ["v1", "v2c"]:
            community = entries.get("community", None)
            if community:
                comm = community.get().strip()
                cmd.extend(["-c", comm])
        elif ver == "v3":
            username = entries.get("username", None)
            if username:
                user = username.get().strip()
                if user:
                    cmd.extend(["-u", user])
            auth_proto = entries.get("auth_proto", tk.StringVar(value="None")).get()
            auth_pass = entries.get("auth_pass", None)
            if auth_proto != "None":
                cmd.extend(["-a", auth_proto])
                if auth_pass:
                    apass = auth_pass.get().strip()
                    if apass:
                        cmd.extend(["-A", apass])
            priv_proto = entries.get("priv_proto", tk.StringVar(value="None")).get()
            priv_pass = entries.get("priv_pass", None)
            if priv_proto != "None":
                cmd.extend(["-x", priv_proto])
                if priv_pass:
                    ppass = priv_pass.get().strip()
                    if ppass:
                        cmd.extend(["-X", ppass])
            # Set security level
            if auth_proto == "None" and priv_proto == "None":
                cmd.extend(["-l", "noAuthNoPriv"])
            elif auth_proto != "None" and priv_proto == "None":
                cmd.extend(["-l", "authNoPriv"])
            elif auth_proto != "None" and priv_proto != "None":
                cmd.extend(["-l", "authPriv"])
        cmd.append(ip)
        cmd.append(oid)
        running_walk[0] = True
        walk_cancel_button.config(state="normal")
        walk_run_button.config(state="disabled")
        thread = threading.Thread(target=execute_cmd_walk, args=(cmd,))
        thread.start()
        check_queue_walk()

    def cancel_snmp():
        if process_walk[0]:
            process_walk[0].kill()
            output_queue_walk.put("\nCancelled\n")
            running_walk[0] = False
            process_walk[0] = None

    walk_run_button.config(command=run_snmp)
    walk_cancel_button.config(command=cancel_snmp)

    # Variables for Trap
    process_trap = [None]
    running_trap = [False]
    output_queue_trap = queue.Queue()
    config_path_trap = [None]

    def check_queue_trap():
        try:
            while True:
                line = output_queue_trap.get_nowait()
                trap_log_text.insert(tk.END, line)
                trap_log_text.see(tk.END)
        except queue.Empty:
            pass
        if running_trap[0]:
            window.after(100, check_queue_trap)
        else:
            trap_stop_button.config(state="disabled")
            trap_start_button.config(state="normal")

    def execute_cmd_trap(cmd, filter_str):
        try:
            process_trap[0] = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding='utf-8', errors='replace', bufsize=1)
            for line in iter(process_trap[0].stdout.readline, ''):
                if not filter_str or filter_str in line:
                    output_queue_trap.put(line)
            process_trap[0].wait()
            if process_trap[0].returncode != 0:
                output_queue_trap.put(f"\nProcess exited with code {process_trap[0].returncode}\n")
        except Exception as e:
            output_queue_trap.put(f"\nError: {str(e)}\n")
        finally:
            running_trap[0] = False
            output_queue_trap.put("\nFinished\n")
            process_trap[0] = None
            if config_path_trap[0]:
                os.unlink(config_path_trap[0])
                config_path_trap[0] = None

    def start_trap():
        if running_trap[0]:
            return
        trap_log_text.delete(1.0, tk.END)
        port = port_entry.get().strip()
        if not port:
            port = "10162"
        try:
            port_num = int(port)
        except ValueError:
            trap_log_text.insert(tk.END, "Invalid port number.\n")
            return
        if port_num < 1024:
            trap_log_text.insert(tk.END, "Note: Ports below 1024 may require running the application with administrator privileges.\n")

        # Check IPv4
        try:
            s4 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s4.bind(('', port_num))
            s4.close()
        except OSError as e:
            if e.errno in (48, 98):  # EADDRINUSE
                trap_log_text.insert(tk.END, f"Port {port} is already in use on IPv4. Please choose a different port or stop the process using it. Try 'sudo lsof -i :{port}' or 'netstat -anv | grep {port}' to find the process.\n")
                return
            elif e.errno == 13:  # EACCES
                trap_log_text.insert(tk.END, f"Permission denied to bind to port {port} on IPv4. Ports below 1024 require root privileges. Run the script with sudo or choose a higher port.\n")
                return
            else:
                trap_log_text.insert(tk.END, f"Error checking port {port} on IPv4: {str(e)}\n")
                return

        # Check IPv6 if available
        try:
            s6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            try:
                s6.bind(('::', port_num, 0, 0))
                s6.close()
            except OSError as e:
                if e.errno in (48, 98):  # EADDRINUSE
                    trap_log_text.insert(tk.END, f"Port {port} is already in use on IPv6. Please choose a different port or stop the process using it. Try 'sudo lsof -i :{port}' or 'netstat -anv | grep {port}' to find the process.\n")
                    return
                elif e.errno == 13:  # EACCES
                    trap_log_text.insert(tk.END, f"Permission denied to bind to port {port} on IPv6. Ports below 1024 require root privileges. Run the script with sudo or choose a higher port.\n")
                    return
                else:
                    raise
        except OSError as e:
            # If creating IPv6 socket fails, likely not supported
            if e.errno in (47, 93, 97, 102):  # EAFNOSUPPORT, EPROTONOSUPPORT, etc.
                pass
            else:
                trap_log_text.insert(tk.END, f"Error checking IPv6 for port {port}: {str(e)}\n")
                return

        filter_str = filter_entry.get().strip()

        config_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
        config_file.write("disableAuthorization yes\n")
        config_file.close()
        config_path_trap[0] = config_file.name
        cmd = ["snmptrapd", "-f", "-Lo", "-c", config_path_trap[0], "udp:" + port]
        running_trap[0] = True
        trap_stop_button.config(state="normal")
        trap_start_button.config(state="disabled")
        thread = threading.Thread(target=execute_cmd_trap, args=(cmd, filter_str))
        thread.start()
        check_queue_trap()

    def stop_trap():
        if process_trap[0]:
            process_trap[0].kill()
            output_queue_trap.put("\nStopped\n")
            running_trap[0] = False
            if config_path_trap[0]:
                os.unlink(config_path_trap[0])
                config_path_trap[0] = None
            process_trap[0] = None

    trap_start_button.config(command=start_trap)
    trap_stop_button.config(command=stop_trap)

    window.mainloop()

if __name__ == "__main__":
    main()
