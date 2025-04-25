import sqlite3
import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import re
import bcrypt
import pandas as pd
from fpdf import FPDF
from datetime import datetime
import threading
from PIL import Image, ImageTk
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


class EmployeeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Employee Management System")

        # Set window to a normal size initially
        self.root.geometry("800x600")
        self.root.resizable(True, True)
        self.root.state('normal')

        # Configure styles
        self.style = ttk.Style()
        self.style.configure('Treeview', rowheight=25)
        self.style.configure('TButton', padding=5)

        # Initialize variables
        self.db_file = "employee.db"
        self.current_user = None
        self.failed_attempts = 0
        self.lockout_time = None
        self.theme_dark = False
        self.language = "english"  # Default language

        # Create backup directory
        if not os.path.exists("backups"):
            os.makedirs("backups")

        self.setup_db()
        self.build_login_screen()

    def setup_db(self):
        with sqlite3.connect(self.db_file) as conn:
            cur = conn.cursor()
            # Users table with additional fields
            cur.execute(""" 
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT NOT NULL,
                    last_login TEXT,
                    failed_attempts INTEGER DEFAULT 0,
                    account_locked INTEGER DEFAULT 0
                )""")
            
            # Enhanced employees table
            cur.execute(""" 
                CREATE TABLE IF NOT EXISTS employees (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    email TEXT,
                    contact TEXT UNIQUE,
                    department TEXT,
                    position TEXT,
                    salary REAL,
                    hire_date TEXT,
                    photo_path TEXT
                )""")
            
            # Audit log table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    action TEXT,
                    timestamp TEXT,
                    details TEXT
                )""")
            conn.commit()

    def log_audit(self, action, details=""):
        with sqlite3.connect(self.db_file) as conn:
            cur = conn.cursor()
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cur.execute("INSERT INTO audit_log (username, action, timestamp, details) VALUES (?, ?, ?, ?)",
                       (self.current_user, action, timestamp, details))
            conn.commit()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def build_login_screen(self):
        self.clear_window()
        self.root.geometry("600x400")
        
        login_frame = tk.Frame(self.root, padx=20, pady=20)
        login_frame.pack(expand=True, fill=tk.BOTH)
        
        tk.Label(login_frame, text="Login", font=("Arial", 24)).pack(pady=20)

        form_frame = tk.Frame(login_frame)
        form_frame.pack(pady=10)

        tk.Label(form_frame, text="Username").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.username_entry = tk.Entry(form_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(form_frame, text="Password").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.password_entry = tk.Entry(form_frame, show="*")
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)

        button_frame = tk.Frame(login_frame)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Login", command=self.login).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Register", command=self.register).pack(side=tk.LEFT, padx=5)
        
        # Add theme toggle button
        tk.Button(button_frame, text="Toggle Theme", command=self.toggle_theme).pack(side=tk.LEFT, padx=5)
        
        # Add language selection
        lang_frame = tk.Frame(login_frame)
        lang_frame.pack(pady=5)
        tk.Label(lang_frame, text="Language:").pack(side=tk.LEFT)
        self.lang_var = tk.StringVar(value="english")
        tk.OptionMenu(lang_frame, self.lang_var, "english", "spanish", "french", command=self.change_language).pack(side=tk.LEFT)

    def toggle_theme(self):
        self.theme_dark = not self.theme_dark
        bg_color = "#2d2d2d" if self.theme_dark else "SystemButtonFace"
        fg_color = "white" if self.theme_dark else "black"
        
        self.root.config(bg=bg_color)
        for widget in self.root.winfo_children():
            self.apply_theme(widget, bg_color, fg_color)
        
        if hasattr(self, 'tree'):
            style = ttk.Style()
            style.configure("Treeview", 
                          background="#3d3d3d" if self.theme_dark else "white",
                          foreground="white" if self.theme_dark else "black",
                          fieldbackground="#3d3d3d" if self.theme_dark else "white")

    def apply_theme(self, widget, bg_color, fg_color):
        if isinstance(widget, (tk.Frame, tk.Label, tk.Button, tk.Entry)):
            widget.config(bg=bg_color, fg=fg_color)
        for child in widget.winfo_children():
            self.apply_theme(child, bg_color, fg_color)

    def change_language(self, language):
        self.language = language
        # In a real app, you would load translations here
        messagebox.showinfo("Info", f"Language changed to {language.capitalize()}")

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        # Check if account is locked
        if self.is_account_locked(username):
            messagebox.showerror("Error", "Account is temporarily locked. Try again later.")
            return
            
        try:
            with sqlite3.connect(self.db_file) as conn:
                conn.row_factory = sqlite3.Row  # Enable dictionary-style access
                cur = conn.cursor()
                # Explicitly select the columns we need
                cur.execute("SELECT username, password, account_locked, failed_attempts FROM users WHERE username=?", (username,))
                result = cur.fetchone()
                
                if result:
                    if result["account_locked"]:  # Now using column name
                        messagebox.showerror("Error", "Account is locked. Contact administrator.")
                        return
                        
                    if bcrypt.checkpw(password.encode('utf-8'), result["password"]):
                        # Reset failed attempts on successful login
                        cur.execute("UPDATE users SET failed_attempts=0, last_login=? WHERE username=?", 
                                  (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), username))
                        conn.commit()
                        
                        self.current_user = username
                        self.failed_attempts = 0
                        self.log_audit("LOGIN", "Successful login")
                        self.build_main_screen(username)
                    else:
                        self.failed_attempts = result["failed_attempts"] + 1
                        cur.execute("UPDATE users SET failed_attempts=? WHERE username=?", 
                                  (self.failed_attempts, username))
                        conn.commit()
                        
                        if self.failed_attempts >= 3:
                            cur.execute("UPDATE users SET account_locked=1 WHERE username=?", (username,))
                            conn.commit()
                            self.log_audit("ACCOUNT_LOCKED", f"Too many failed attempts for {username}")
                            messagebox.showerror("Error", "Too many failed attempts. Account locked.")
                        else:
                            messagebox.showerror("Error", f"Invalid credentials. {3-self.failed_attempts} attempts remaining")
                else:
                    messagebox.showerror("Error", "Username not found")
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Database error: {e}")

    def is_account_locked(self, username):
        try:
            with sqlite3.connect(self.db_file) as conn:
                conn.row_factory = sqlite3.Row  # Enable dictionary-style access
                cur = conn.cursor()
                cur.execute("SELECT account_locked FROM users WHERE username=?", (username,))
                result = cur.fetchone()
                return result and result["account_locked"]  # Access by column name
        except sqlite3.Error:
            return False
        
    def register(self):
        self.clear_window()
        self.root.geometry("600x500")
        
        register_frame = tk.Frame(self.root, padx=20, pady=20)
        register_frame.pack(expand=True, fill=tk.BOTH)
        
        tk.Label(register_frame, text="Register", font=("Arial", 24)).pack(pady=20)

        form_frame = tk.Frame(register_frame)
        form_frame.pack(pady=10)

        tk.Label(form_frame, text="Username").grid(row=0, column=0, sticky="e", padx=5, pady=5)
        self.reg_username_entry = tk.Entry(form_frame)
        self.reg_username_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Label(form_frame, text="Password (min 8 chars)").grid(row=1, column=0, sticky="e", padx=5, pady=5)
        self.reg_password_entry = tk.Entry(form_frame, show="*")
        self.reg_password_entry.grid(row=1, column=1, padx=5, pady=5)

        self.password_strength_label = tk.Label(form_frame, text="Password Strength: ", fg="red")
        self.password_strength_label.grid(row=2, column=1, sticky="w", padx=5)

        self.reg_password_entry.bind("<KeyRelease>", self.check_password_strength)

        button_frame = tk.Frame(register_frame)
        button_frame.pack(pady=10)

        tk.Button(button_frame, text="Submit", command=self.submit_registration).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Back to Login", command=self.build_login_screen).pack(side=tk.LEFT, padx=5)

    def check_password_strength(self, event=None):
        password = self.reg_password_entry.get()
        strength = self.validate_password_strength(password)
        color = "green" if strength.startswith("Strong") else "orange" if strength.startswith("Medium") else "red"
        self.password_strength_label.config(text=f"Password Strength: {strength}", fg=color)

    def validate_password_strength(self, password):
        if len(password) < 8:
            return "Weak: Must be at least 8 characters"
        
        missing = []
        if not re.search(r"[A-Z]", password):
            missing.append("uppercase letter")
        if not re.search(r"[a-z]", password):
            missing.append("lowercase letter")
        if not re.search(r"\d", password):
            missing.append("number")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            missing.append("special character")
        
        if missing:
            return f"Medium: Missing {', '.join(missing)}"
        return "Strong"

    def submit_registration(self):
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()

        if not username or not password:
            messagebox.showerror("Error", "Username and password cannot be empty")
            return

        strength = self.validate_password_strength(password)
        if strength != "Strong":
            messagebox.showerror("Error", "Password is too weak! " + strength)
            return

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            with sqlite3.connect(self.db_file) as conn:
                cur = conn.cursor()
                cur.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                          (username, hashed_password))
                conn.commit()
                self.log_audit("REGISTER", f"New user: {username}")
                messagebox.showinfo("Success", "Registered Successfully")
                self.build_login_screen()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")
        except sqlite3.Error as e:
            messagebox.showerror("Error", f"Database error: {e}")

    def build_main_screen(self, username):
        self.root.geometry("1000x700")
        self.clear_window()
        
        # Main container
        main_container = tk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True)
        
        # Header frame
        header_frame = tk.Frame(main_container, pady=10)
        header_frame.pack(fill=tk.X)
        
        tk.Label(header_frame, text=f"Welcome, {username}", font=("Arial", 16)).pack(side=tk.LEFT, padx=10)
        
        # Button frame
        button_frame = tk.Frame(header_frame)
        button_frame.pack(side=tk.RIGHT, padx=10)
        
        tk.Button(button_frame, text="Profile", command=self.open_profile_management).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Dashboard", command=self.show_dashboard).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Logout", command=self.build_login_screen).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Backup DB", command=self.backup_database).pack(side=tk.LEFT, padx=5)
        
        # Main content frame
        content_frame = tk.Frame(main_container)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Employee form frame
        form_frame = tk.LabelFrame(content_frame, text="Add/Edit Employee", padx=10, pady=10)
        form_frame.pack(fill=tk.X, pady=5)
        
        # Form fields
        fields = ["Name", "Email", "Contact", "Department", "Position", "Salary", "Hire Date (YYYY-MM-DD)"]
        self.entry_vars = {}

        for i, field in enumerate(fields):
            tk.Label(form_frame, text=field).grid(row=i//2, column=(i%2)*2, sticky="e", padx=5, pady=5)
            entry = tk.Entry(form_frame)
            entry.grid(row=i//2, column=(i%2)*2+1, sticky="ew", padx=5, pady=5)
            self.entry_vars[field.lower().split()[0]] = entry
        
        # Photo upload button
        self.photo_path = ""
        tk.Button(form_frame, text="Upload Photo", command=self.upload_photo).grid(row=3, column=2, columnspan=2, pady=5)
        
        # Form buttons
        form_btn_frame = tk.Frame(form_frame)
        form_btn_frame.grid(row=4, column=0, columnspan=4, pady=10)
        
        tk.Button(form_btn_frame, text="Add", command=self.add_employee).pack(side=tk.LEFT, padx=5)
        tk.Button(form_btn_frame, text="Clear", command=self.clear_form).pack(side=tk.LEFT, padx=5)
        
        # Search frame
        search_frame = tk.Frame(content_frame)
        search_frame.pack(fill=tk.X, pady=5)
        
        tk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(search_frame, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.search_var.trace("w", self.search_employee)
        
        search_options = ["Name", "Email", "Contact", "Department", "Position"]
        self.search_by_var = tk.StringVar(value="Name")
        search_by_menu = tk.OptionMenu(search_frame, self.search_by_var, *search_options)
        search_by_menu.pack(side=tk.LEFT, padx=5)
        
        # Employee treeview
        tree_frame = tk.Frame(content_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        columns = ("ID", "Name", "Email", "Contact", "Department", "Position", "Salary", "Hire Date")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100, anchor="w")
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Action buttons
        action_frame = tk.Frame(content_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(action_frame, text="View All", command=self.view_employees).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Edit Selected", command=self.edit_employee).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Delete Selected", command=self.delete_employee).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Export to Excel", command=self.export_excel).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Export to PDF", command=self.export_pdf).pack(side=tk.LEFT, padx=5)
        tk.Button(action_frame, text="Generate Report", command=self.generate_report).pack(side=tk.LEFT, padx=5)
        
        # Bind double click to edit
        self.tree.bind("<Double-1>", lambda e: self.edit_employee())
        
        # Load initial data
        self.view_employees()

    def upload_photo(self):
        filepath = filedialog.askopenfilename(filetypes=[("Image Files", "*.jpg *.jpeg *.png")])
        if filepath:
            self.photo_path = filepath
            messagebox.showinfo("Success", "Photo selected")

    def clear_form(self):
        for entry in self.entry_vars.values():
            entry.delete(0, tk.END)
        self.photo_path = ""

    def show_dashboard(self):
        dashboard = tk.Toplevel(self.root)
        dashboard.title("Employee Dashboard")
        dashboard.geometry("800x600")
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                # Department distribution
                df = pd.read_sql_query("SELECT department, COUNT(*) as count FROM employees GROUP BY department", conn)
                
                fig1 = plt.Figure(figsize=(5, 4), dpi=100)
                ax1 = fig1.add_subplot(111)
                df.plot(kind='pie', y='count', labels=df['department'], autopct='%1.1f%%', ax=ax1)
                ax1.set_title('Department Distribution')
                
                canvas1 = FigureCanvasTkAgg(fig1, dashboard)
                canvas1.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
                
                # Salary distribution
                df = pd.read_sql_query("SELECT position, AVG(salary) as avg_salary FROM employees GROUP BY position", conn)
                
                fig2 = plt.Figure(figsize=(5, 4), dpi=100)
                ax2 = fig2.add_subplot(111)
                df.plot(kind='bar', x='position', y='avg_salary', ax=ax2)
                ax2.set_title('Average Salary by Position')
                
                canvas2 = FigureCanvasTkAgg(fig2, dashboard)
                canvas2.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate dashboard: {str(e)}")

    def backup_database(self):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = f"backups/employee_backup_{timestamp}.db"
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                conn.backup(sqlite3.connect(backup_file))
            self.log_audit("BACKUP", f"Database backed up to {backup_file}")
            messagebox.showinfo("Success", f"Database backed up to {backup_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Backup failed: {str(e)}")

    def add_employee(self):
        # Get form data
        name = self.entry_vars['name'].get().strip()
        email = self.entry_vars['email'].get().strip()
        contact = self.entry_vars['contact'].get().strip()
        department = self.entry_vars['department'].get().strip()
        position = self.entry_vars['position'].get().strip()
        salary = self.entry_vars['salary'].get().strip()
        hire_date = self.entry_vars['hire'].get().strip()
        
        # Validate inputs
        if not name:
            messagebox.showerror("Error", "Name cannot be empty")
            return
            
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            messagebox.showerror("Error", "Invalid email format")
            return
            
        if not salary.replace('.', '').isdigit():
            messagebox.showerror("Error", "Salary must be a number")
            return
            
        try:
            datetime.strptime(hire_date, "%Y-%m-%d")
        except ValueError:
            messagebox.showerror("Error", "Hire date must be in YYYY-MM-DD format")
            return
            
        try:
            with sqlite3.connect(self.db_file) as conn:
                cur = conn.cursor()
                cur.execute("""
                    INSERT INTO employees 
                    (name, email, contact, department, position, salary, hire_date, photo_path) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (name, email, contact, department, position, float(salary), hire_date, self.photo_path))
                conn.commit()
                
                self.log_audit("ADD_EMPLOYEE", f"Added employee: {name}")
                messagebox.showinfo("Success", "Employee added successfully")
                self.clear_form()
                self.view_employees()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Contact number already exists")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to add employee: {str(e)}")

    def view_employees(self):
        try:
            with sqlite3.connect(self.db_file) as conn:
                df = pd.read_sql_query("SELECT id, name, email, contact, department, position, salary, hire_date FROM employees", conn)
                
                # Clear existing data
                for row in self.tree.get_children():
                    self.tree.delete(row)
                    
                # Insert new data
                for _, row in df.iterrows():
                    self.tree.insert("", tk.END, values=tuple(row))
                    
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load employees: {str(e)}")

    def search_employee(self, *args):
        search_term = self.search_var.get().lower()
        search_by = self.search_by_var.get().lower()
        
        if not search_term:
            self.view_employees()
            return
            
        try:
            with sqlite3.connect(self.db_file) as conn:
                query = f"""
                    SELECT id, name, email, contact, department, position, salary, hire_date 
                    FROM employees 
                    WHERE LOWER({search_by}) LIKE ?
                """
                params = (f"%{search_term}%",)
                df = pd.read_sql_query(query, conn, params=params)
                
                # Clear existing data
                for row in self.tree.get_children():
                    self.tree.delete(row)
                    
                # Insert new data
                for _, row in df.iterrows():
                    self.tree.insert("", tk.END, values=tuple(row))
                    
        except Exception as e:
            messagebox.showerror("Error", f"Search failed: {str(e)}")

    def edit_employee(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an employee to edit")
            return
            
        emp_id = self.tree.item(selected[0])['values'][0]
        
        try:
            with sqlite3.connect(self.db_file) as conn:
                cur = conn.cursor()
                cur.execute("SELECT * FROM employees WHERE id=?", (emp_id,))
                employee = cur.fetchone()
                
                if employee:
                    # Populate form fields
                    self.clear_form()
                    self.entry_vars['name'].insert(0, employee[1])
                    self.entry_vars['email'].insert(0, employee[2])
                    self.entry_vars['contact'].insert(0, employee[3])
                    self.entry_vars['department'].insert(0, employee[4])
                    self.entry_vars['position'].insert(0, employee[5])
                    self.entry_vars['salary'].insert(0, str(employee[6]))
                    self.entry_vars['hire'].insert(0, employee[7])
                    self.photo_path = employee[8] if employee[8] else ""
                    
                    # Change Add button to Update
                    for widget in self.root.winfo_children():
                        if isinstance(widget, tk.Button) and widget['text'] == "Add":
                            widget.config(text="Update", command=lambda: self.update_employee(emp_id))
                            break
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load employee: {str(e)}")

    def update_employee(self, emp_id):
        # Get form data
        name = self.entry_vars['name'].get().strip()
        email = self.entry_vars['email'].get().strip()
        contact = self.entry_vars['contact'].get().strip()
        department = self.entry_vars['department'].get().strip()
        position = self.entry_vars['position'].get().strip()
        salary = self.entry_vars['salary'].get().strip()
        hire_date = self.entry_vars['hire'].get().strip()
        
        # Validate inputs
        if not name:
            messagebox.showerror("Error", "Name cannot be empty")
            return
            
        try:
            with sqlite3.connect(self.db_file) as conn:
                cur = conn.cursor()
                cur.execute("""
                    UPDATE employees 
                    SET name=?, email=?, contact=?, department=?, position=?, salary=?, hire_date=?, photo_path=?
                    WHERE id=?
                """, (name, email, contact, department, position, float(salary), hire_date, self.photo_path, emp_id))
                conn.commit()
                
                self.log_audit("UPDATE_EMPLOYEE", f"Updated employee ID: {emp_id}")
                messagebox.showinfo("Success", "Employee updated successfully")
                self.clear_form()
                self.view_employees()
                
                # Change Update button back to Add
                for widget in self.root.winfo_children():
                    if isinstance(widget, tk.Button) and widget['text'] == "Update":
                        widget.config(text="Add", command=self.add_employee)
                        break
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update employee: {str(e)}")

    def delete_employee(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an employee to delete")
            return
            
        emp_id = self.tree.item(selected[0])['values'][0]
        emp_name = self.tree.item(selected[0])['values'][1]
        
        if messagebox.askyesno("Confirm", f"Are you sure you want to delete {emp_name}?"):
            try:
                with sqlite3.connect(self.db_file) as conn:
                    cur = conn.cursor()
                    cur.execute("DELETE FROM employees WHERE id=?", (emp_id,))
                    conn.commit()
                    
                    self.log_audit("DELETE_EMPLOYEE", f"Deleted employee ID: {emp_id}")
                    messagebox.showinfo("Success", "Employee deleted successfully")
                    self.view_employees()
            except Exception as e:
                messagebox.showerror("Error", f"Failed to delete employee: {str(e)}")

    def export_excel(self):
        try:
            with sqlite3.connect(self.db_file) as conn:
                df = pd.read_sql_query("SELECT name, email, contact, department, position, salary, hire_date FROM employees", conn)
                
                filepath = filedialog.asksaveasfilename(
                    defaultextension=".xlsx",
                    filetypes=[("Excel files", "*.xlsx"), ("All files", "*.*")]
                )
                
                if filepath:
                    df.to_excel(filepath, index=False)
                    self.log_audit("EXPORT_EXCEL", f"Exported to {filepath}")
                    messagebox.showinfo("Success", f"Data exported to {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")

    def export_pdf(self):
        try:
            with sqlite3.connect(self.db_file) as conn:
                df = pd.read_sql_query("SELECT name, email, contact, department, position, salary, hire_date FROM employees", conn)
                
                pdf = FPDF()
                pdf.add_page()
                pdf.set_font("Arial", size=12)
                
                # Title
                pdf.cell(200, 10, txt="Employee Report", ln=1, align="C")
                pdf.ln(10)
                
                # Add date
                pdf.cell(200, 10, txt=f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
                pdf.ln(10)
                
                # Table header
                pdf.set_font("Arial", "B", size=10)
                col_widths = [40, 40, 30, 30, 30, 20, 30]
                headers = ["Name", "Email", "Contact", "Department", "Position", "Salary", "Hire Date"]
                
                for i, header in enumerate(headers):
                    pdf.cell(col_widths[i], 10, txt=header, border=1)
                pdf.ln()
                
                # Table rows
                pdf.set_font("Arial", size=8)
                for _, row in df.iterrows():
                    for i, col in enumerate(row):
                        pdf.cell(col_widths[i], 10, txt=str(col), border=1)
                    pdf.ln()
                
                filepath = filedialog.asksaveasfilename(
                    defaultextension=".pdf",
                    filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
                )
                
                if filepath:
                    pdf.output(filepath)
                    self.log_audit("EXPORT_PDF", f"Exported to {filepath}")
                    messagebox.showinfo("Success", f"PDF exported to {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"PDF export failed: {str(e)}")

    def generate_report(self):
        report_window = tk.Toplevel(self.root)
        report_window.title("Generate Report")
        report_window.geometry("400x300")
        
        tk.Label(report_window, text="Report Options", font=("Arial", 14)).pack(pady=10)
        
        # Report type selection
        tk.Label(report_window, text="Report Type:").pack()
        report_type = tk.StringVar(value="department")
        tk.OptionMenu(report_window, report_type, "department", "position", "hire_date").pack()
        
        # Date range for hire date reports
        date_frame = tk.Frame(report_window)
        date_frame.pack(pady=10)
        
        tk.Label(date_frame, text="From:").grid(row=0, column=0)
        start_date = tk.Entry(date_frame)
        start_date.grid(row=0, column=1)
        
        tk.Label(date_frame, text="To:").grid(row=1, column=0)
        end_date = tk.Entry(date_frame)
        end_date.grid(row=1, column=1)
        
        # Generate button
        tk.Button(
            report_window, 
            text="Generate", 
            command=lambda: self.run_report(report_type.get(), start_date.get(), end_date.get())
        ).pack(pady=20)

    def run_report(self, report_type, start_date, end_date):
        try:
            with sqlite3.connect(self.db_file) as conn:
                if report_type == "department":
                    query = "SELECT department, COUNT(*) as count, AVG(salary) as avg_salary FROM employees GROUP BY department"
                    df = pd.read_sql_query(query, conn)
                    
                elif report_type == "position":
                    query = "SELECT position, COUNT(*) as count, AVG(salary) as avg_salary FROM employees GROUP BY position"
                    df = pd.read_sql_query(query, conn)
                    
                elif report_type == "hire_date":
                    if not start_date or not end_date:
                        messagebox.showerror("Error", "Please enter both start and end dates")
                        return
                        
                    query = """
                        SELECT strftime('%Y-%m', hire_date) as month, 
                               COUNT(*) as count, 
                               AVG(salary) as avg_salary 
                        FROM employees 
                        WHERE hire_date BETWEEN ? AND ?
                        GROUP BY strftime('%Y-%m', hire_date)
                    """
                    df = pd.read_sql_query(query, conn, params=(start_date, end_date))
                
                # Show report in new window
                report_view = tk.Toplevel(self.root)
                report_view.title(f"{report_type.capitalize()} Report")
                report_view.geometry("600x400")
                
                # Create treeview
                tree = ttk.Treeview(report_view, columns=list(df.columns), show="headings")
                for col in df.columns:
                    tree.heading(col, text=col)
                    tree.column(col, width=100)
                
                # Insert data
                for _, row in df.iterrows():
                    tree.insert("", tk.END, values=tuple(row))
                
                tree.pack(fill=tk.BOTH, expand=True)
                
                # Export button
                tk.Button(
                    report_view,
                    text="Export to Excel",
                    command=lambda: self.export_report_to_excel(df, report_type)
                ).pack(pady=10)
                
                self.log_audit("GENERATE_REPORT", f"Generated {report_type} report")
                
        except Exception as e:
            messagebox.showerror("Error", f"Report generation failed: {str(e)}")

    def export_report_to_excel(self, df, report_type):
        try:
            filepath = filedialog.asksaveasfilename(
                defaultextension=".xlsx",
                filetypes=[("Excel files", "*.xlsx")],
                initialfile=f"{report_type}_report.xlsx"
            )
            
            if filepath:
                df.to_excel(filepath, index=False)
                self.log_audit("EXPORT_REPORT", f"Exported {report_type} report to {filepath}")
                messagebox.showinfo("Success", f"Report exported to {filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")

    def open_profile_management(self):
        profile_window = tk.Toplevel(self.root)
        profile_window.title("Profile Management")
        profile_window.geometry("400x400")
        
        tk.Label(profile_window, text="Profile Management", font=("Arial", 14)).pack(pady=10)
        
        # Current password
        tk.Label(profile_window, text="Current Password:").pack()
        current_pass = tk.Entry(profile_window, show="*")
        current_pass.pack()
        
        # New username
        tk.Label(profile_window, text="New Username:").pack()
        new_username = tk.Entry(profile_window)
        new_username.pack()
        
        # New password
        tk.Label(profile_window, text="New Password:").pack()
        new_password = tk.Entry(profile_window, show="*")
        new_password.pack()
        
        # Password strength
        pass_strength = tk.Label(profile_window, text="Password Strength: ", fg="red")
        pass_strength.pack()
        new_password.bind("<KeyRelease>", lambda e: self.update_password_strength(new_password.get(), pass_strength))
        
        # Buttons
        button_frame = tk.Frame(profile_window)
        button_frame.pack(pady=10)
        
        tk.Button(
            button_frame, 
            text="Change Username", 
            command=lambda: self.change_username(current_pass.get(), new_username.get())
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            button_frame, 
            text="Change Password", 
            command=lambda: self.change_password(current_pass.get(), new_password.get())
        ).pack(side=tk.LEFT, padx=5)
        
        tk.Button(
            button_frame,
            text="Delete Account",
            command=lambda: self.delete_account(current_pass.get(), profile_window)
        ).pack(side=tk.LEFT, padx=5)

    def update_password_strength(self, password, label):
        strength = self.validate_password_strength(password)
        color = "green" if strength.startswith("Strong") else "orange" if strength.startswith("Medium") else "red"
        label.config(text=f"Password Strength: {strength}", fg=color)

    def change_username(self, current_password, new_username):
        if not current_password or not new_username:
            messagebox.showerror("Error", "Current password and new username are required")
            return
            
        try:
            with sqlite3.connect(self.db_file) as conn:
                cur = conn.cursor()
                cur.execute("SELECT password FROM users WHERE username=?", (self.current_user,))
                result = cur.fetchone()
                
                if result and bcrypt.checkpw(current_password.encode('utf-8'), result[0]):
                    cur.execute("UPDATE users SET username=? WHERE username=?", (new_username, self.current_user))
                    conn.commit()
                    
                    self.current_user = new_username
                    self.log_audit("CHANGE_USERNAME", f"Changed username to {new_username}")
                    messagebox.showinfo("Success", "Username changed successfully")
                else:
                    messagebox.showerror("Error", "Current password is incorrect")
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change username: {str(e)}")

    def change_password(self, current_password, new_password):
        if not current_password or not new_password:
            messagebox.showerror("Error", "Current and new passwords are required")
            return
            
        strength = self.validate_password_strength(new_password)
        if strength != "Strong":
            messagebox.showerror("Error", "New password is too weak! " + strength)
            return
            
        try:
            with sqlite3.connect(self.db_file) as conn:
                cur = conn.cursor()
                cur.execute("SELECT password FROM users WHERE username=?", (self.current_user,))
                result = cur.fetchone()
                
                if result and bcrypt.checkpw(current_password.encode('utf-8'), result[0]):
                    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
                    cur.execute("UPDATE users SET password=? WHERE username=?", (hashed_password, self.current_user))
                    conn.commit()
                    
                    self.log_audit("CHANGE_PASSWORD", "Password changed")
                    messagebox.showinfo("Success", "Password changed successfully")
                else:
                    messagebox.showerror("Error", "Current password is incorrect")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to change password: {str(e)}")

    def delete_account(self, current_password, window=None):
        if not current_password:
            messagebox.showerror("Error", "Current password is required")
            return
            
        try:
            with sqlite3.connect(self.db_file) as conn:
                cur = conn.cursor()
                cur.execute("SELECT password FROM users WHERE username=?", (self.current_user,))
                result = cur.fetchone()
                
                if result and bcrypt.checkpw(current_password.encode('utf-8'), result[0]):
                    if messagebox.askyesno("Confirm", "Are you sure you want to delete your account? This cannot be undone!"):
                        # Delete user
                        cur.execute("DELETE FROM users WHERE username=?", (self.current_user,))
                        
                        # Delete user's employees (optional)
                        cur.execute("DELETE FROM employees")
                        
                        conn.commit()
                        
                        self.log_audit("DELETE_ACCOUNT", "Account deleted")
                        messagebox.showinfo("Success", "Account deleted successfully")
                        
                        if window:
                            window.destroy()
                        self.build_login_screen()
                else:
                    messagebox.showerror("Error", "Current password is incorrect")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete account: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = EmployeeApp(root)
    root.mainloop()