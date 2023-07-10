from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from tkinter import filedialog
import subprocess
import socket
from datetime import datetime


class ScanningPort:
    def __init__(self, master):
        master.title('NiKtO')
        master.geometry("800x600")  # Set the window size
        master.configure(background="#f2f2f2")

        self.style = ttk.Style()
        self.style.configure('TFrame', background="#f2f2f2")
        self.style.configure('TButton', background="#fff")
        self.style.configure('TLabel', background="#f2f2f2")
        self.style.configure('TSeparator', background="#f2f2f2")
        self.style.configure('Header.TLabel' ,font=('didot 20 bold italic'), background="#f2f2f2")

        # Create a main frame
        self.main_frame = ttk.Frame(master)
        self.main_frame.pack(fill=BOTH, expand=True)

        # Frame 1
        # self.frame_header = ttk.Frame(master)
        # self.frame_header.pack()
        
        self.frame_header = ttk.Frame(self.main_frame)
        self.frame_header.pack(side=TOP, pady=10)

        ttk.Label(self.frame_header, text="NIKTO", style='Header.TLabel',font="didot 50 bold ").grid(row=0, column=1, padx=10,pady=10, sticky='sw')
        # ttk.Separator(self.frame_header, orient=HORIZONTAL).grid(row=1, columnspan=5, sticky="ew", padx=10, pady=15)

        # Frame 2
        # self.frame_content = ttk.Frame(master)
        # self.frame_content.config(width=600)
        # self.frame_content.pack()

        self.frame_content = ttk.Frame(self.main_frame)
        self.frame_content.pack(side=TOP, pady=10)

        ttk.Label(self.frame_content, text="Enter Target URL Address: ", font=('didot 20 bold italic')).grid(row=0, column=0, padx=10, pady=15)

        self.entry_name = ttk.Entry(self.frame_content, width=35)
        self.entry_name.grid(row=1, column=0, padx=10)

        # Additional features: Scanning profiles
        self.scanning_profiles = {
            "Default": "",
            "Web Server": "-p 80",
            "Web Application": "-Plugins @webapp"
            # Add more profiles as needed
        }

        self.selected_profile = StringVar()
        self.selected_profile.set("Default")

        ttk.Label(self.frame_content, text="Scanning Profile: ", font=('didot 20 bold italic')).grid(row=2, column=0, padx=10, pady=15)

        profile_dropdown = ttk.OptionMenu(self.frame_content, self.selected_profile, *self.scanning_profiles.keys())
        profile_dropdown.grid(row=2, column=1, padx=10, pady=15, sticky='w')

        # Additional features: SSL/TLS Support
        self.ssl_support = BooleanVar()
        self.ssl_support.set(False)

        check_button = ttk.Checkbutton(self.frame_content, text="SSL/TLS Support", variable=self.ssl_support )
        check_button.grid(row=3, column=0, padx=10, pady=15, sticky='w')
        check_button.configure(style='TCheckbutton')

            # Additional features: Customizable Scans
        self.custom_scan_options = StringVar()
        self.custom_scan_options.set("")

        ttk.Label(self.frame_content, text="Custom Scan Options: ",
                  font=('didot 20 bold italic')).grid(row=4, column=0, padx=10, pady=15)

        # Create a dropdown menu for custom scan options
        self.custom_options_dropdown = ttk.Combobox(self.frame_content, textvariable=self.custom_scan_options,
                                                    state='readonly', width=20)
        self.custom_options_dropdown.grid(row=4, column=1, padx=10)

        # Set the available options for the dropdown
        self.custom_options_dropdown['values'] = (
            "-n 10",
            "-t 5",
            "-id username:password",  # Basic authentication with username and password
            "-Cgidirs all",  # Scan all CGI directories
            "-mutate 3",  # Perform mutation tests (3 levels)
            "-port 80,443",  # Specify custom ports to scan (e.g., 80 and 443)
            "-404code",  # Show the HTTP status code for 404 responses
            "-list-plugins",  # List available plugins
            "-Tuning 2",  # Set the tuning level (1-5)
        )



        # Frame 3
        self.frame_report = ttk.Frame(self.main_frame)
        # self.frame_report.config(height=5, width=600)
        # self.frame_report.pack()
        self.frame_report.pack(side=TOP, pady=10)

        self.txt = Text(self.frame_report, width=100, height=15,font=('didot 20 bold italic'))
        self.txt.grid(row=2, column=0, sticky=W, padx=10, pady=10)
        self.txt.insert(0.0, 'Nikto Scanning Report will appear here...')

        # Buttons
        ttk.Button(self.frame_content, text="Scan", command=self.dscan, width=10).grid(row=7, column=0, padx=5, pady=10,sticky='e')
        ttk.Button(self.frame_content, text="Clear", command=self.clear, width=10).grid(row=7, column=1, padx=5, pady=10,sticky='w')
        ttk.Button(self.frame_content, text="Save Result", command=self.save_result, width=12).grid(row=7, column=2, padx=5,pady=10, sticky='e')
        self.style.configure('TCheckbutton',font=('didot 20 bold italic'))  # Set the font for the Checkbutton

        # Exit button
        ttk.Button(self.frame_report, text="Exit", command=master.quit, width=10).grid(row=6, column=0, padx=10, pady=15, sticky='se')

        # Configure row and column weights to make frames equally sized
        self.main_frame.grid_rowconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.main_frame.grid_rowconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

    def dscan(self):
        self.txt.delete(0.0, END)
        t1 = datetime.now()
        remote_address = self.entry_name.get()

        try:
            # Resolve the hostname to an IP address if the input is a domain name
            remote_ip = socket.gethostbyname(remote_address)
        except socket.gaierror as e:
            messagebox.showerror("Error", f"Failed to resolve hostname: {remote_address}")
            return

        selected_profile = self.selected_profile.get()
        profile_options = self.scanning_profiles[selected_profile].split()

        if self.ssl_support.get():
            profile_options += " -ssl"

        custom_options = self.custom_scan_options.get()

        if custom_options:
            profile_options += custom_options

        # Get the entered ports and split them into a list
        # ports = self.entry_ports.get().split(",")

        # Execute Nikto command with ports
        nik = subprocess.Popen(["nikto", "-host", f"http://{remote_ip}"] + profile_options,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = nik.communicate()

        if output:
            self.txt.insert(END, output.decode("utf-8"))
        if error:
            self.txt.insert(END, error.decode("utf-8"))

        t2 = datetime.now()
        total = t2 - t1
        print("Scanning Completed in: ", total)
        messagebox.showinfo(title="Report Status!", message="Scanning Process Completed")

    def save_result(self):
        result = self.txt.get(0.0, END)
        file_path = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text Files', '*.txt')])
        if file_path:
            with open(file_path, 'w') as file:
                file.write(result)
            messagebox.showinfo(title="Save Result", message="Result saved successfully!")
        else:
            messagebox.showinfo(title="Save Result", message="Saving result canceled.")


    def clear(self):
        self.entry_name.delete(0, 'end')
        self.txt.delete(0.0, 'end')



def main():
    root = Tk()
    scan = ScanningPort(root)

    # Customize the window properties if needed
    root.iconbitmap("icon.ico")  # Set a custom window icon

    # Start the main event loop
    root.mainloop()


if __name__ == '__main__':
    main()
