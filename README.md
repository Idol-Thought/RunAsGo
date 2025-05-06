# RunAsGo

**RunAsGo** is a minimal Windows utility written in Go that executes a PowerShell script in the context of the currently active (interactive) user session. It is designed for use in SYSTEM-level environments like scheduled tasks, services, or endpoint management scripts where direct interaction with the desktop user is otherwise not possible.

---

## ✨ Features

- Finds the first `WTSActive` user session (console or RDP)
- Queries and duplicates the user’s token
- Launches a PowerShell script as that user, with UI access
- Works from SYSTEM context (e.g., PsExec, SCCM, Chef, etc.)
- CLI flag to specify the script to run

---

## 🚀 Usage

```powershell
RunAsGo.exe --ps1 "C:\Path\To\your-script.ps1"
```

This will:

    Locate the first active user session

    Duplicate the user's token

    Launch the given .ps1 script as that user, with access to the desktop and UI

📁 Example: Notifying Users

You can pair RunAsGo with a PowerShell script like restart-notifications.ps1 that:

    Uses BurntToast to show toast notifications

    Prompts the user to reboot

    Logs or handles snooze behavior

```powershell
# Sample use via SYSTEM context:
RunAsGo.exe --ps1 "C:\Scripts\restart-notifications.ps1"
```

🔒 Requirements

    Windows 10/11 or Windows Server 2016+

    Run from SYSTEM, Administrator, or service-level context

    The target user must be logged in and active

    powershell.exe must be accessible in PATH

🧠 How It Works

Under the hood, RunAsGo:

    Enumerates all WTS sessions

    Finds the first with WTSActive state and a valid username

    Uses WTSQueryUserToken + DuplicateTokenEx

    Launches powershell.exe using CreateProcessAsUser

This allows you to bridge SYSTEM-to-user execution without needing hardcoded credentials or interactively logging in.
