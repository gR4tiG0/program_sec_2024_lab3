#!/usr/bin/env python3
import tkinter as tk
from tkinter import messagebox, simpledialog
from tkinter import ttk
from controllers.security_controller import checkLogin, changePassword, initDB, DBLoader, endSession
from controllers.admin_controller import getUsers, updateUser, createUser, deleteUser
from controllers.log_controller import getLogs
from controllers.crypto_controller import checkPass
from errors import *
from sig_check import check, get_system_info_hash

class LoginWindow(tk.Frame):
    def __init__(self, master, *args, **kwargs):
        tk.Frame.__init__(self, master, *args, **kwargs)

        self.menu = tk.Menu(master)
        master.config(menu=self.menu)

        self.info_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Info", menu=self.info_menu)
        self.info_menu.add_command(label="About Program", command=self.about_program)

        self.username_label = tk.Label(self, text="Username")
        self.username_label.pack()

        self.username_entry = tk.Entry(self)
        self.username_entry.pack()

        self.password_label = tk.Label(self, text="Password")
        self.password_label.pack()

        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()

        self.login_button = tk.Button(self, text="Login", command=self.login)
        self.login_button.pack()

        self.master = master

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        log_res = checkLogin(username, password, self.master.ld)

        if "Error" in log_res:
            messagebox.showerror("Error", log_res["Error"])
        elif ("Info" in log_res) and log_res["Info"] == CHANGE_PASS_ERR:
            self.master.current_user = log_res['user']
            messagebox.showinfo("Info", CHANGE_PASS_ERR)
            self.change_password()
        else:
            self.master.current_user = log_res
            role = log_res["role"]

            if role == "admin":
                self.pack_forget()
                self.master.show_admin_window()
            else:
                self.pack_forget()
                self.master.show_user_window()

    def change_password(self):
        self.change_password_window = ChangePasswordWindow(self)

    def about_program(self):
        messagebox.showinfo("Program security, lab 1", "Program created by Prikhodko Yuriy")

class UserWindow(tk.Frame):
    def __init__(self, master, *args, **kwargs):
        tk.Frame.__init__(self, master, *args, **kwargs)

        self.menu = tk.Menu(master)
        master.config(menu=self.menu)

        self.info_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Info", menu=self.info_menu)
        self.info_menu.add_command(label="About Program", command=self.about_program)

        self.change_password_button = tk.Button(self, text="Change Password", command=self.change_password)
        self.change_password_button.pack()
        self.logout_button = tk.Button(self, text="Logout", command=self.logout)
        self.logout_button.pack()

        self.master = master

    def change_password(self):
        self.change_password_window = ChangePasswordWindow(self)

    def logout(self):
        self.pack_forget()
        self.master.show_login_window()

    def about_program(self):
        messagebox.showinfo("Program security, lab 1", "Program created by Prikhodko Yuriy")

class ChangePasswordWindow(tk.Toplevel):
    def __init__(self, master, *args, **kwargs):
        tk.Toplevel.__init__(self, master, *args, **kwargs)
        self.title("Change Password")
        self.geometry("300x200")

        self.old_password_label = tk.Label(self, text="Old Password")
        self.old_password_label.pack()

        self.old_password_entry = tk.Entry(self, show="*")
        self.old_password_entry.pack()

        self.new_password_label = tk.Label(self, text="New Password")
        self.new_password_label.pack()

        self.new_password_entry = tk.Entry(self, show="*")
        self.new_password_entry.pack()

        self.confirm_password_label = tk.Label(self, text="Confirm New Password")
        self.confirm_password_label.pack()

        self.confirm_password_entry = tk.Entry(self, show="*")
        self.confirm_password_entry.pack()

        self.submit_button = tk.Button(self, text="Submit", command=self.submit)
        self.submit_button.pack()

        self.master = master

    def submit(self):
        old_password = self.old_password_entry.get()
        new_password = self.new_password_entry.get()
        confirm_password = self.confirm_password_entry.get()



        if new_password == confirm_password:
            cur_user = self.master.master.current_user
            change_res = changePassword(old_password, new_password, cur_user, self.master.master.ld)
            if "Error" in change_res:
                messagebox.showerror("Error", change_res["Error"])
            else:
                messagebox.showinfo("Success", "Password successfully changed")
                self.destroy()
        else:
            messagebox.showerror("Error", PASS_MATCH_ERR)

class LogWindow(tk.Toplevel):
    def __init__(self, master, *args, **kwargs):
        tk.Toplevel.__init__(self, master, *args, **kwargs)
        self.title("Logs")

        self.tree = ttk.Treeview(self, columns=('Date', 'Type', 'Message'), show='headings')
        self.tree.heading('Date', text='Date')
        self.tree.heading('Type', text='Type')
        self.tree.heading('Message', text='Message')
        self.tree.column('Date', width=140)
        self.tree.column('Type', width=60)
        self.tree.column('Message', width=800)
        self.tree.pack(side='left', fill='y')

        self.scrollbar = ttk.Scrollbar(self, orient='vertical', command=self.tree.yview)
        self.scrollbar.pack(side='right', fill='y')

        self.tree.configure(yscrollcommand=self.scrollbar.set)

        self.logs = getLogs()

        for log in self.logs:
            self.tree.insert('', 'end', values=(log['date'], log['type'], log['message']))

        self.master = master
        self.update_idletasks()
        width = self.winfo_reqwidth()
        height = self.winfo_reqheight()
        self.geometry(f"{width}x{height}")

class AdminWindow(UserWindow):
    def __init__(self, master, *args, **kwargs):
        UserWindow.__init__(self, master, *args, **kwargs)

        self.list_users_button = tk.Button(self, text="List Users", command=self.list_users)
        self.list_users_button.pack()
        self.show_logs_button = tk.Button(self, text="Show Logs", command=self.show_logs)
        self.show_logs_button.pack()

    def list_users(self):
        self.list_users_window = ListUsersWindow(self)
    def show_logs(self):
        self.log_window = LogWindow(self)

class CreateUserWindow(tk.Toplevel):
    def __init__(self, master, *args, **kwargs):
        tk.Toplevel.__init__(self, master, *args, **kwargs)
        self.title("Create User")
        self.geometry("200x100")

        self.username_label = tk.Label(self, text="Username")
        self.username_label.pack()

        self.username_entry = tk.Entry(self)
        self.username_entry.pack()

        self.submit_button = tk.Button(self, text="Submit", command=self.submit)
        self.submit_button.pack()

        self.master = master

    def submit(self):
        username = self.username_entry.get()
        res = createUser(username, self.master.master.master.ld)
        if "Error" in res:
            messagebox.showerror("Error", res["Error"])
        else:
            self.master.add_user(res["username"])
            self.destroy()

class ConfirmDeleteWindow(tk.Toplevel):
    def __init__(self, master, username, *args, **kwargs):
        tk.Toplevel.__init__(self, master, *args, **kwargs)
        self.title("Confirm Delete")
        self.geometry("200x100")

        self.password_label = tk.Label(self, text="Admin Password")
        self.password_label.pack()

        self.password_entry = tk.Entry(self, show="*")
        self.password_entry.pack()

        self.submit_button = tk.Button(self, text="Submit", command=self.submit)
        self.submit_button.pack()

        self.master = master
        self.username = username

    def submit(self):
        password = self.password_entry.get()
        res = deleteUser(self.username, password, self.master.master.master.current_user["username"], self.master.master.master.ld)
        if "Error" in res:
            messagebox.showerror("Error", res["Error"])
        else:
            self.master.delete_user(self.username)
            self.destroy()

class ListUsersWindow(tk.Toplevel):
    def __init__(self, master, *args, **kwargs):
        tk.Toplevel.__init__(self, master, *args, **kwargs)
        self.title("List Users")


        self.tree = ttk.Treeview(self, columns=('Username', 'Role', 'Restriction', 'Ban', 'Delete'), show='headings')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Role', text='Role')
        self.tree.heading('Restriction', text='Restriction')
        self.tree.heading('Ban', text='Ban')
        self.tree.heading('Delete', text='Delete')
        self.tree.pack()

        self.users = getUsers(self.master.master.ld)

        for username, user_info in self.users.items():
            self.tree.insert('', 'end', text=username, values=(username, user_info['role'], user_info['restricted'], user_info['banned'], 'Delete user'))

        self.tree.bind('<Button-1>', self.toggle_value)

        self.create_user_button = tk.Button(self, text="Create New User", command=self.create_user)
        self.create_user_button.pack(side='left')

        self.save_button = tk.Button(self, text="Save Changes", command=self.save_changes)
        self.save_button.pack(side='right')

        self.master = master
        self.update_idletasks()
        width = self.winfo_reqwidth()
        height = self.winfo_reqheight()
        self.geometry(f"{width}x{height}")

    def toggle_value(self, event):
        column = self.tree.identify_column(event.x)
        item = self.tree.identify_row(event.y)
        try:
            if column == '#3':  # Restriction column
                restriction = self.tree.item(item, 'values')[2]
                new_v = "Yes" if restriction == "No" else "No"
                self.tree.set(item, column, new_v)
            elif column == '#4':  # Ban column
                ban = self.tree.item(item, 'values')[3]
                new_v = "Yes" if ban == "No" else "No"
                self.tree.set(item, column, new_v)
            elif column == '#5':  # Delete column
                username = self.tree.item(item, 'values')[0]
                self.confirm_delete_window = ConfirmDeleteWindow(self, username)
        except IndexError:
            pass

    def save_changes(self):
        for item in self.tree.get_children():
            item_values = self.tree.item(item)['values']
            username = item_values[0]
            restriction = item_values[2]
            ban = item_values[3]
            res = updateUser(username, restriction, ban, self.master.master.ld)
            if "Error" in res:
                messagebox.showerror("Error", res["Error"])
        self.destroy()

    def create_user(self):
        self.create_user_window = CreateUserWindow(self)

    def add_user(self, username):
        self.tree.insert('', 'end', values=(username, 'user', 'No', 'No', 'Delete user'))

    def delete_user(self, username):
        for item in self.tree.get_children():
            if self.tree.item(item, 'values')[0] == username:
                self.tree.delete(item)
                break

class MainWindow(tk.Frame):
    def __init__(self, master, *args, **kwargs):
        tk.Frame.__init__(self, master, *args, **kwargs)

        self.menu = tk.Menu(master)
        master.config(menu=self.menu)

        self.info_menu = tk.Menu(self.menu, tearoff=0)
        self.menu.add_cascade(label="Info", menu=self.info_menu)
        self.info_menu.add_command(label="About Program", command=self.about_program)

        self.master = master

    def about_program(self):
        messagebox.showinfo("About Program", "This is a sample GUI application")

class App(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.title("App")
        self.geometry("300x200")
        self.current_user = None
        self.login_window = LoginWindow(self)
        self.login_window.pack()

        self.ld = None
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def on_close(self):
        endSession(self.ld)
        self.destroy()

    def show_login_window(self):
        self.login_window = LoginWindow(self)
        self.login_window.pack()

    def show_main_window(self):
        self.main_window = MainWindow(self)
        self.main_window.pack()

    def show_user_window(self):
        self.main_window = UserWindow(self)
        self.main_window.pack()

    def show_admin_window(self):
        self.main_window = AdminWindow(self)
        self.main_window.pack()

if __name__ == "__main__":
    info_hash = get_system_info_hash()
    passwd = simpledialog.askstring("Password", "Enter DB password:", show='*')
    salt = checkPass(passwd)
    print(salt)
    if salt == None:
        messagebox.showinfo("Error", "Invalid DataBase Password")
    elif check(info_hash):
        print("initing db")
        initDB(passwd, salt)
        app = App()
        ld = DBLoader(passwd, salt)
        app.ld = ld
        app.mainloop()
    else:
        messagebox.showinfo("Error", "Invalid Signature")