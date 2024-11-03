import tkinter as tk
from tkinter import ttk, messagebox
import random
import string

# Initialize window
root = tk.Tk()
root.title("Password Generator & Strength Checker")
root.geometry("700x600")
root.configure(bg='#e9ecef')

# Global styles
LABEL_FONT = ("Helvetica", 12, "italic")  # Italic font for labels
TITLE_FONT = ("Helvetica", 16, "bold", "italic")  # Italic font for titles
BUTTON_FONT = ("Helvetica", 12, "bold", "italic")  # Italic font for buttons
BUTTON_BG = "#2A0E49"
BUTTON_FG = "#ffffff"
BOLD_ITALIC_FONT = ("Helvetica", 12, "bold", "italic")  # Bold and Italic font for specific labels

# Function to switch between modes
def switch_mode(mode):
    if mode == 'generator':
        frame_strength_checker.pack_forget()
        frame_password_generator.pack(pady=20)
        frame_mode_selection.pack_forget()  # Hide the mode selection frame
    elif mode == 'checker':
        frame_password_generator.pack_forget()
        frame_strength_checker.pack(pady=20)
        frame_mode_selection.pack_forget()  # Hide the mode selection frame

# Function to show the mode selection frame
def show_mode_selection():
    frame_password_generator.pack_forget()
    frame_strength_checker.pack_forget()
    frame_mode_selection.pack(pady=20)  # Show the mode selection frame

# Password Strength Evaluation Function
def check_password_strength(password):
    length = len(password)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    # Determine strength based on complexity and constraints
    if length >= 12 and has_lower and has_upper and has_digit and has_special:
        strength = 'Strong'
    elif length >= 8 and (has_lower + has_upper + has_digit + has_special >= 3):
        strength = 'Medium'
    else:
        strength = 'Weak'

    # Determine color based on strength
    if strength == 'Strong':
        color = 'green'
    elif strength == 'Medium':
        color = 'orange'
    else:
        color = 'red'

    # Determine which label to update based on visible frame
    if frame_password_generator.winfo_ismapped():
        label_strength.config(text=f"Password Strength: {strength}", fg=color)
    elif frame_strength_checker.winfo_ismapped():
        label_strength_checker.config(text=f"Password Strength: {strength}", fg=color)

# Password Generator Function
def generate_password():
    length = scale_length.get()

    include_lower = var_lower.get()
    include_upper = var_upper.get()
    include_digits = var_digits.get()
    include_special = var_special.get()

    characters = ''
    if include_lower:
        characters += string.ascii_lowercase
    if include_upper:
        characters += string.ascii_uppercase
    if include_digits:
        characters += string.digits
    if include_special:
        characters += string.punctuation

    if characters:
        password = ''.join(random.choice(characters) for _ in range(length))
        entry_password.delete(0, tk.END)
        entry_password.insert(0, password)
        label_strength.config(text="Password Strength: ")  # Reset strength label
        label_strength.config(fg='black')  # Reset color
    else:
        messagebox.showwarning("Selection Error", "Select at least one option")

# Password Strength Checker for Custom Input
def check_custom_password():
    password = entry_custom_password.get()
    if password:
        check_password_strength(password)
    else:
        messagebox.showwarning("Input Error", "Please enter a password to check")

# Password Strength Checker Function (for generator)
def check_generated_password_strength():
    password = entry_password.get()
    if password:
        check_password_strength(password)
    else:
        messagebox.showwarning("Input Error", "No password generated to check")

# Initial Frame for Mode Selection
frame_mode_selection = tk.Frame(root, bg='#e9ecef')
frame_mode_selection.pack(pady=20)

# Welcome Label
welcome_label = tk.Label(frame_mode_selection, text="Welcome to the App!", font=TITLE_FONT, bg='#e9ecef')
welcome_label.pack(pady=10)

# Mode Selection Buttons
btn_gen_mode = tk.Button(frame_mode_selection, text="Password Generator", font=BUTTON_FONT, bg=BUTTON_BG, fg=BUTTON_FG, command=lambda: switch_mode('generator'))
btn_gen_mode.pack(side=tk.LEFT, padx=20)

btn_check_mode = tk.Button(frame_mode_selection, text="Password Strength Checker", font=BUTTON_FONT, bg=BUTTON_BG, fg=BUTTON_FG, command=lambda: switch_mode('checker'))
btn_check_mode.pack(side=tk.LEFT, padx=20)

# Frame for Password Generator
frame_password_generator = tk.Frame(root, bg='#e9ecef')

tk.Label(frame_password_generator, text="Password Generator", font=TITLE_FONT, bg='#e9ecef').pack(pady=10)

tk.Label(frame_password_generator, text="Length of Password:", font=BOLD_ITALIC_FONT, bg='#e9ecef').pack(pady=(10, 0))

# Use a Scale to choose the length of the password (8 to 120 characters) with default value 8
scale_length = tk.Scale(frame_password_generator, from_=8, to=120, orient=tk.HORIZONTAL, length=300, bg='#e9ecef', font=LABEL_FONT, highlightbackground='#e9ecef')
scale_length.set(8)  # Set default value to 8
scale_length.pack(pady=5)

# Options for character inclusion using toggle buttons
var_lower = tk.BooleanVar(value=False)
var_upper = tk.BooleanVar(value=False)
var_digits = tk.BooleanVar(value=False)
var_special = tk.BooleanVar(value=False)

switch_frame = tk.Frame(frame_password_generator, bg='#e9ecef')
switch_frame.pack(pady=10)

tk.Label(switch_frame, text="Include Lowercase:", font=LABEL_FONT, bg='#e9ecef').grid(row=0, column=0, sticky='w')
ttk.Checkbutton(switch_frame, variable=var_lower).grid(row=0, column=1)

tk.Label(switch_frame, text="Include Uppercase:", font=LABEL_FONT, bg='#e9ecef').grid(row=1, column=0, sticky='w')
ttk.Checkbutton(switch_frame, variable=var_upper).grid(row=1, column=1)

tk.Label(switch_frame, text="Include Numbers:", font=LABEL_FONT, bg='#e9ecef').grid(row=2, column=0, sticky='w')
ttk.Checkbutton(switch_frame, variable=var_digits).grid(row=2, column=1)

tk.Label(switch_frame, text="Include Special Characters:", font=LABEL_FONT, bg='#e9ecef').grid(row=3, column=0, sticky='w')
ttk.Checkbutton(switch_frame, variable=var_special).grid(row=3, column=1)

# Entry to display generated password
entry_password = tk.Entry(frame_password_generator, width=30, font=("Helvetica", 12, "italic"), relief=tk.GROOVE, bd=2)
entry_password.pack(pady=10)

# Generate Password Button
btn_generate = tk.Button(frame_password_generator, text="Generate Password", font=BUTTON_FONT, bg=BUTTON_BG, fg=BUTTON_FG, command=generate_password)
btn_generate.pack(pady=5)

# Check Strength Button
btn_check_strength_gen = tk.Button(frame_password_generator, text="Check Strength", font=BUTTON_FONT, bg=BUTTON_BG, fg=BUTTON_FG, command=check_generated_password_strength)
btn_check_strength_gen.pack(pady=5)

# Label for Strength Result
label_strength = tk.Label(frame_password_generator, text="Password Strength: ", font=BOLD_ITALIC_FONT, bg='#e9ecef')
label_strength.pack(pady=5)

# Frame for Password Strength Checker
frame_strength_checker = tk.Frame(root, bg='#e9ecef')

tk.Label(frame_strength_checker, text="Password Strength Checker", font=TITLE_FONT, bg='#e9ecef').pack(pady=10)

# Entry for Custom Password Strength Check
entry_custom_password = tk.Entry(frame_strength_checker, width=30, font=("Helvetica", 12, "italic"), relief=tk.GROOVE, bd=2)
entry_custom_password.pack(pady=10)

# Check Strength Button for Custom Input
btn_check_strength = tk.Button(frame_strength_checker, text="Check Strength", font=BUTTON_FONT, bg=BUTTON_BG, fg=BUTTON_FG, command=check_custom_password)
btn_check_strength.pack(pady=5)

# Label for Strength Result in Checker
label_strength_checker = tk.Label(frame_strength_checker, text="Password Strength: ", font=BOLD_ITALIC_FONT, bg='#e9ecef')
label_strength_checker.pack(pady=5)

# Show initial mode selection frame
show_mode_selection()

# Start the application
root.mainloop()
