# Identity and Access Management (IAM) Web Application

## Project Overview

This project is a simple Identity and Access Management (IAM) web application developed using Python, Flask, and SQLite. It provides user registration, authentication, role-based access control, user management, security logging, and alerts for repeated failed login attempts.

The project demonstrates basic IAM concepts and security monitoring practices.

## Objectives

- Implement secure user registration and login.
- Apply Role-Based Access Control (RBAC).
- Allow administrators to manage user accounts and roles.
- Record important security events.
- Detect repeated failed login attempts and generate security alerts.

## Technologies Used

- **Python 3** – Application logic
- **Flask** – Web application framework
- **SQLite** – Database
- **bcrypt** – Password hashing
- **HTML** – Web page structure
- **Visual Studio Code** – Development environment

## Features

### 1. User Registration
Users can create accounts with a username and password.

### 2. User Authentication
The application verifies login credentials and manages user sessions.

### 3. Role-Based Access Control
The application supports two roles:
- **Admin:** Can access administrative features and manage users.
- **User:** Can access regular user features.

### 4. User Management
Administrators can view users, change roles, and delete other user accounts. The application prevents administrators from deleting their own accounts or changing their own roles through the protected actions.

### 5. Security Logs
The application records events such as registrations, successful and failed logins, logouts, role changes, and user deletions.

### 6. Security Alerts
The application generates an alert when five failed login attempts for a username occur within ten minutes. This can help identify possible brute-force login activity.

## Database Design

The application uses an SQLite database named `database.db`.

### Users Table
Stores user account information, including usernames, password hashes, and roles.

### Security Logs Table
Stores security-related events, including usernames, event descriptions, and timestamps.

## How to Run the Project

1. Install Python 3.
2. Open the project folder in Visual Studio Code.
3. Open the terminal and activate your virtual environment.
4. Install the required packages if needed:

   ```bash
   pip install flask bcrypt
   ```

5. Run the application:

   ```bash
   python app.py
   ```

6. Open your browser and visit:

   `http://127.0.0.1:5000`

## Security Considerations

- Passwords are hashed using bcrypt rather than stored as plain text.
- Administrative routes should be restricted to authorized administrators.
- Security events are recorded for review.
- Repeated failed logins generate alerts.

**Note:** This is a learning project, not a production-ready IAM system. Production deployment requires additional protections, including secure secret-key management, HTTPS, CSRF protection, stronger input validation, and appropriate account lockout or rate-limiting controls.

## Future Enhancements

- Email notifications for security alerts
- Multi-factor authentication (MFA)
- Password reset functionality
- More detailed audit logs
- Improved dashboard and reporting
- Automated security testing

## Conclusion

This project demonstrates fundamental IAM concepts, including authentication, authorization, role management, and security event monitoring, using a small Flask web application.
