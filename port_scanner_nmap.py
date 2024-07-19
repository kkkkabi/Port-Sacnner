# Group 46
# S360233 Kabi Li
# S360496 Chen Chen

# please install libraries: python-namp, reportlab to run the application
# pip install python-nmap reportlab

import tkinter as tk
import tkinter.messagebox as messagebox
import nmap
import re
import threading
import time
from tkinter import ttk
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Table, TableStyle,Spacer, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
import datetime

class PortScannerApp:
    def __init__(self, master):
        self.master = master
        self.master.title("Port Scanner")
        self.scan_stopped = False  # Flag to indicate if scanning should stop
        self.scanning_thread = None  # Reference to the scanning thread

        # Variables for IP address, start port, and end port
        self.ip_address = tk.StringVar()
        self.ip_address.set("192.168.0.184")
        self.start_port = tk.IntVar()
        self.start_port.set(1)
        self.end_port = tk.IntVar()
        self.end_port.set(65535)

        # Create frame for input fields and buttons
        input_frame = ttk.LabelFrame(self.master, text="Port Scanner")
        input_frame.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        # Labels and entry fields for IP address, start port, and end port
        ttk.Label(input_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5, sticky="e")
        self.ip_entry = ttk.Entry(input_frame, textvariable=self.ip_address, width=50)
        self.ip_entry.grid(row=0, column=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Port From:").grid(row=1, column=0, padx=5, pady=5, sticky="e")
        self.start_port_entry = ttk.Entry(input_frame, textvariable=self.start_port, width=50)
        self.start_port_entry.grid(row=1, column=1, padx=5, pady=5)
        
        ttk.Label(input_frame, text="Port To:").grid(row=2, column=0, padx=5, pady=5, sticky="e")
        self.end_port_entry = ttk.Entry(input_frame, textvariable=self.end_port, width=50)
        self.end_port_entry.grid(row=2, column=1, padx=5, pady=5)
        
        # Buttons for start, stop scanning, and clear results
        self.start_button = ttk.Button(input_frame, text="Start", command=self.start_scan)
        self.start_button.grid(row=0, column=2, padx=10, pady=5)

        self.stop_button = ttk.Button(input_frame, text="Stop", command=self.stop_scan)
        self.stop_button.grid(row=1, column=2, padx=10, pady=5)

        self.clear_button = ttk.Button(input_frame, text="Clear Result", command=self.clear_results)
        self.clear_button.grid(row=2, column=2, padx=10, pady=5)

        # Display scan results
        self.result_tree = ttk.Treeview(input_frame, columns=("IP Address", "Port", "Status"), show="headings", height=10)
        self.result_tree.heading("IP Address", text="IP Address")
        self.result_tree.heading("Port", text="Port")
        self.result_tree.heading("Status", text="Status")
        self.result_tree.grid(row=4, column=0, columnspan=3, padx=5, pady=5)

        # Add scrollbar
        scroll_y = ttk.Scrollbar(input_frame, orient="vertical", command=self.result_tree.yview)
        self.result_tree.configure(yscrollcommand=scroll_y.set)
        scroll_y.grid(row=4, column=3, sticky="ns")

        # Inside the __init__ method of PortScannerApp class, after creating other buttons
        self.export_button = ttk.Button(input_frame, text="Export to PDF", command=self.export_to_pdf)
        self.export_button.grid(row=5, column=0, columnspan=3, padx=10, pady=5, sticky="we")

        # Create a label to display the running message
        self.running_label = ttk.Label(input_frame, text="Scanning is in progress. Please do not close the application until the report is generated.", foreground="red")
        self.running_label.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky="w")
        self.running_label.grid_remove()  # Initially hide the message

    def input_validate(self, ip_address, start_port, end_port):
        ip_address = self.ip_address.get()
        start_port = self.start_port.get()
        end_port = self.end_port.get()

        # IP address should be IPv4 address
        ip_address_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

        # Validate if the input is valid
        if ip_address_pattern.search(ip_address) is None:
            messagebox.showerror("Error", "Please enter a valid IP address.")
            return False
        
        if start_port < 1 or start_port > 65535 or end_port < 0 or end_port > 65535:
            messagebox.showerror("Error", "Please enter valid port ranges")
            return False
        
        if start_port > end_port:
            messagebox.showerror("Error", "Start Port can't be greater than end port.")
            return False

        return True

    def start_scan(self):

        # Display the running message
        self.running_label.grid(row=3, column=0, columnspan=3, padx=5, pady=5, sticky="w")

        
        # Reset the scan_stopped flag
        self.scan_stopped = False

        # Get the value from Tkinter
        ip_address = self.ip_address.get()
        start_port = self.start_port.get()
        end_port = self.end_port.get()

        # Call the input validation function to check if the input is correct
        if not self.input_validate(ip_address, start_port, end_port):
            return
        
        # Delete previous scan results
        self.result_tree.delete(*self.result_tree.get_children())

        # Start scanning in a separate thread
        self.scanning_thread = threading.Thread(target=self.scan_ports, args=(ip_address, start_port, end_port))
        self.scanning_thread.start()

    def stop_scan(self):
        # Set the scan_stopped flag to True
        self.scan_stopped = True

    def scan_ports(self, ip_address, start_port, end_port):

        # Use Nmap to scan the ports in the specified range
        nm = nmap.PortScanner()
        for port in range(start_port, end_port + 1):
            try:
                if self.scan_stopped:
                    messagebox.showinfo("Scanning Stopped", "Scanning has been stopped.")
                    return

                result = nm.scan(ip_address, str(port))
                # Handle potential KeyError if the keys are not present
                try:
                    port_status = result['scan'][ip_address]['tcp'][port]['state']

                except KeyError:
                    port_status = "Unknown"  # Set a default value if the keys are not present

                self.result_tree.insert("", "end", values=(ip_address, port, port_status, time.strftime("%Y-%m-%d %H:%M:%S") ))
                print(f"{ip_address} port{port} is {port_status}")


                # Adjust scrollbar position
                self.result_tree.yview_moveto(1.0)  # Move to the bottom


            except nmap.PortScannerError as e:
                messagebox.showerror("Error", f"An error occurred while scanning port # {port}: {e}")

                # Check if the user wants to stop scanning
                if self.scan_stopped:
                    messagebox.showinfo("Scanning Stopped", "Scanning has been stopped.")
                    return

        # Display message when the scan is complete
        messagebox.showinfo("Scan Complete", "Port scanning has been completed.")
        # Hide the running message when the scan is complete
        self.running_label.grid_forget()
        
    def clear_results(self):
        # Clear the content of the result_tree
        self.result_tree.delete(*self.result_tree.get_children())
        
    def export_to_pdf(self):
        ip_address = self.ip_address.get()
        start_port = self.start_port.get()
        end_port = self.end_port.get()
        
        # Check if a scan has been performed
        if not ip_address or not self.result_tree.get_children():
            messagebox.showerror("Error", "Please perform a scan before exporting the PDF report.")
            return
        
        currenttime = time.strftime("%Y-%m-%d %H:%M:%S")
        report_filename = f"port_scan_report_{currenttime}.pdf"
        doc = SimpleDocTemplate(report_filename, pagesize=letter)
        styles = getSampleStyleSheet()

        # Port Scan Result Tree
        data = [["IP Address", "Ports", "Status", "Timestamp"]]
        open_ports = []
        closed_ports = []
        filtered_ports = []
        for child in self.result_tree.get_children():
            values = self.result_tree.item(child)["values"]
            data.append(values)
            status = values[2]
            if status == "open":
                open_ports.append(values)
            elif status == "closed":
                closed_ports.append(values)
            else:
                filtered_ports.append(values)

        elements = []

        

        # Title
        elements.append(Paragraph("Scan Port Report", styles['Title']))
        elements.append(Paragraph("Group 46", styles['Normal']))
        elements.append(Paragraph("S360233 Kabi Li", styles['Normal']))
        elements.append(Paragraph("S360496 Chen Chen", styles['Normal']))
        elements.append(Paragraph("-"*100, styles['Normal']))

        # Report Summary
        elements.append(Paragraph("Report Summary", styles['Heading3']))
        elements.append(Paragraph(f"IP Address: {ip_address}", styles['Normal']))
        elements.append(Paragraph(f"Port Range: From {start_port} to {end_port}", styles['Normal']))
        elements.append(Paragraph(f"There are {len(open_ports)} ports open.", styles['Normal']))
        elements.append(Paragraph(f"There are {len(closed_ports)} ports closed.", styles['Normal']))
        elements.append(Paragraph(f"There are {len(filtered_ports)} ports filtered.", styles['Normal']))
        elements.append(Paragraph("-"*100, styles['Normal']))

        elements.append(Paragraph("Open Ports List", styles['Heading3']))

        # Create a open port table
        if open_ports:
            formatted_data_open_port = [data[0]]  # Header row
            for row in open_ports:
                formatted_row = [row[0], row[1], row[2], row[3]]  # Add timestamp
                formatted_data_open_port.append(formatted_row)

            open_ports_table = Table(formatted_data_open_port)
            open_ports_table_style = [
                ('GRID', (0, 0), (-1, -1), 1, (0, 0, 0)),  # Add grid lines
                ('FONT', (0, 0), (-1, -1), 'Helvetica', 8),  # Change font to Helvetica with size 8
                ('LEFTPADDING', (0, 0), (-1, -1), 2),  # Add left padding
                ('RIGHTPADDING', (0, 0), (-1, -1), 2),  # Add right padding
                ('TOPPADDING', (0, 0), (-1, -1), 1),  # Add top padding
                ('BOTTOMPADDING', (0, 0), (-1, -1), 1),  # Add bottom padding
            ]
            open_ports_table.setStyle(TableStyle(open_ports_table_style))  # Add grid lines
            elements.append(open_ports_table)
        else:
            elements.append(Paragraph("There is no open port."))
            elements.append(Spacer(1, 8))

          # Add a page break, move port scan result to second page
        elements.append(PageBreak())

       # Scanned Port Details
        elements.append(Paragraph("Scan Port Results", styles['Heading3']))
        elements.append(Spacer(1, 8))  # Add spacer for line break

        # Create a table with detail ports
        formatted_data = [data[0]]  # Header row
        for row in data[1:]:
            formatted_row = [row[0], row[1], row[2],row[3]]  # Add timestamp
            formatted_data.append(formatted_row)

        # Create the table
        table = Table(formatted_data)
        
        # Define the style for the table
        table_style = [
            ('GRID', (0, 0), (-1, -1), 1, (0, 0, 0)),  # Add grid lines
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 8),  # Change font to Helvetica with size 8
            ('LEFTPADDING', (0, 0), (-1, -1), 2),  # Add left padding
            ('RIGHTPADDING', (0, 0), (-1, -1), 2),  # Add right padding
            ('TOPPADDING', (0, 0), (-1, -1), 1),  # Add top padding
            ('BOTTOMPADDING', (0, 0), (-1, -1), 1),  # Add bottom padding
        ]
        for row in range(1, len(data)):
            status = data[row][2]
            if status == "open":
                table_style.append(('BACKGROUND', (0, row), (-1, row), colors.yellow))  # Set background color for data rows where the status is "open"
        
        # Apply the style to the table
        table.setStyle(TableStyle(table_style))
            
        elements.append(table)

        doc.build(elements)
        
        messagebox.showinfo("Export Complete", f"Report exported to {report_filename}")

def main():
    root = tk.Tk()
    app = PortScannerApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
