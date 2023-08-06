import os
import time
import paramiko
import re
import glob
from ftplib import FTP
import logging

MIKROTIK_INFO = [
    {
        "ip": "IP",
        "username": "user",
        "password": "pass",
    },
    # Pridajte dalsie MikroTik zariadenia do tohto zoznamu, ak je to potrebne
]

FTP_INFO = {
    "server": "IP",
    "username": "user",
    "password": "pass",
    "directory": "/path/...",
}

# Upravte cestu tak, aby obsahovala root priecinok
LOCAL_DIRECTORY = "/path/..."

# Nastavenie logovania
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger()

def log(message):
    print(message)  # Vypis logu na konzolu
    logger.info(message)  # Zapis logu do suboru

# Zvysenie levelu logovania pre paramiko, aby sme videli aj detaily o pripojeniach
paramiko_logger = logging.getLogger("paramiko")
paramiko_logger.setLevel(logging.INFO)

# Zvysenie levelu logovania pre ftplib, aby sme videli aj detaily o pripojeniach
ftplib_logger = logging.getLogger("ftplib")
ftplib_logger.setLevel(logging.INFO)
		
def backup_mikrotik(mikrotik_info):
    logger.info("Zalohujem MikroTik " + mikrotik_info["ip"])
    logger.info("#"*50)

    try:
        # Zvysime logovanie detailov pri kazdom pripojeni
        log(f"Pripajam sa na MikroTik {mikrotik_info['ip']}...")
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(mikrotik_info["ip"], username=mikrotik_info["username"], password=mikrotik_info["password"])
        log(f"Pripojenie na MikroTik {mikrotik_info['ip']} bolo uspesne")
		
		# Inicializujeme ssh_shell
        ssh_shell = client.invoke_shell()
        time.sleep(1)
        ssh_shell.recv(1000)  # Precitaj a ignoruj vystup z prikazu

        # Vymazeme vsetky .backup subory zo zariadenia MikroTik pred vytvorenim novej zalohy
        log("Zacinam vymazavat vsetky .backup subory zo zariadenia MikroTik...")
        stdin, stdout, stderr = client.exec_command(':foreach i in=[/file find where name~".backup"] do={/file remove $i}')
        response = stdout.read()
        if response:
            log(f"Odozva od MikroTik: {response.decode('utf-8')}")
        time.sleep(10)
        log("Vsetky .backup subory boli vymazane zo zariadenia MikroTik")

        ssh_shell.send('system identity print\r\n')
        time.sleep(2)
        identity_output = ssh_shell.recv(1000).decode('utf-8')

        # Ziskajme identitu zariadenia pomocou regex vyhladavania
        match = re.search(r"\[.*@(.*)\]", identity_output)
        if match:
            identity = match.group(1)
            log(f"Ziskana identita zariadenia: {identity}")
        else:
            log("Nepodarilo sa ziskat identitu zariadenia z vystupu")
            return

        # Nahradenie neziaducich znakov v identite zariadenia
        safe_identity = identity.replace("/", "-").replace(" ", "_")
        log(f"Upravena identita zariadenia pre pouzitie v nazve suboru: {safe_identity}")

        date = time.strftime("%Y%m%d")  # Get current date
        log(f"Aktualne datum pre pridanie do nazvu suboru: {date}")

        # Vytvorime .backup subor na zariadeni MikroTik
        backup_file = f"/flash/{safe_identity}_{mikrotik_info['ip']}_{date}.backup"
        log(f"Vytvaram .backup subor s nazvom: {backup_file}")
        ssh_shell.send(f'/system backup save name={backup_file} password=""\r\n')
        time.sleep(20)  # Pockame 20 sekund na dokoncenie zalohy
        log(f".backup subor {backup_file} bol uspesne vytvoreny")

        # Prevedieme .backup subor na .rsc subor
        rsc_file = f"{backup_file}.rsc"
        log(f"Prevadzam .backup subor na .rsc format s nazvom: {rsc_file}")
        ssh_shell.send(f'/export file={rsc_file}\r\n')
        time.sleep(20)  # Pockame 20 sekund na dokoncenie exportu
        log(f".rsc subor {rsc_file} bol uspesne vytvoreny")

        # Stiahneme subory do lokalnej zlozky
        log("Zacina stahovanie suborov do lokalnej zlozky...")
        transport = paramiko.Transport(mikrotik_info["ip"])
        transport.connect(username=mikrotik_info["username"], password=mikrotik_info["password"])
        sftp = paramiko.SFTPClient.from_transport(transport)
        
        # Stiahnutie .rsc suboru
        local_rsc_filename = os.path.basename(rsc_file)
        sftp.get(rsc_file, os.path.join(LOCAL_DIRECTORY, local_rsc_filename))

        
        # Stiahnutie .backup suboru
        local_backup_filename = os.path.basename(backup_file)
        sftp.get(backup_file, os.path.join(LOCAL_DIRECTORY, local_backup_filename))

        
        sftp.close()
        transport.close()
        log("Stahovanie suborov dokoncene")

        # Vymazeme .rsc subory obsahujuce slovo "backup" zo zariadenia MikroTik
        log("Zacinam vymazavat .rsc subory obsahujuce slovo 'backup' zo zariadenia MikroTik...")
        ssh_shell.send(':foreach i in=[/file find where (name~".rsc") && (name~"backup")] do={/file remove $i}\r\n')
        time.sleep(10)
        log(".rsc subory obsahujuce slovo 'backup' boli vymazany zo zariadenia MikroTik")

        client.close()

        log(f"Zaloha MikroTik {mikrotik_info['ip']} uspesne dokoncena")

        return rsc_file, backup_file

    except Exception as e:
        log(f"Nastala chyba pri zalohovani: {str(e)}")

        # Ak je nejaka chyba, vypiseme detailnejsie informacie
        import traceback
        traceback_message = traceback.format_exc()
        log(traceback_message)

    # Zvyraznime koniec zalohovania
    log("#"*50)
	
def upload_to_ftp(local_file_path, remote_file_name):
    log("Pripajam sa na FTP server...")
    ftp = FTP(FTP_INFO["server"])
    ftp.login(user=FTP_INFO["username"], passwd=FTP_INFO["password"])
    log(f"Nasledujuci subor sa bude pokusat nahrat na FTP: {local_file_path}")
    with open(local_file_path, 'rb') as fp:
        try:
            ftp.storbinary(f'STOR {FTP_INFO["directory"]}/{remote_file_name}', fp)
        except Exception as e:
            log(f"Nastala chyba pri nahravani na FTP: {str(e)}")
            import traceback
            traceback_message = traceback.format_exc()
            log(traceback_message)
    ftp.quit()
    log("Nahranie na FTP ukoncene")
	
def clean_local_directory(directory, extension, max_files):
    log(f"Cistenie priecinka {directory} pre subory s koncovkou {extension}...")
    files = sorted(glob.glob(os.path.join(directory, f"*{extension}")), key=os.path.getctime)
    if len(files) > max_files:
        files_to_remove = len(files) - max_files
        log(f"Najdenych {len(files)} suborov. Mazem {files_to_remove} najstarsich suborov.")
        for _ in range(files_to_remove):
            os.remove(files[0])
            log(f"Vymazany subor: {files[0]}")
            del files[0]
    else:
        log(f"Pocet suborov v {directory} je v ramci limitu.")

def clean_ftp_directory(ftp, directory, extension, max_files):
    log(f"Cistenie FTP priecinka {directory} pre subory s koncovkou {extension}...")
    ftp.cwd(directory)
    files = sorted([(name, ftp.sendcmd('MDTM ' + name)) for name in ftp.nlst() if name.endswith(extension)], key=lambda x: x[1])
    if len(files) > max_files:
        files_to_remove = len(files) - max_files
        log(f"Najdenych {len(files)} suborov na FTP. Mazem {files_to_remove} najstarsich suborov.")
        for _ in range(files_to_remove):
            ftp.delete(files[0][0])
            log(f"Vymazany subor na FTP: {files[0][0]}")
            del files[0]
    else:
        log(f"Pocet suborov v {directory} na FTP je v ramci limitu.")

if __name__ == "__main__":
    for mikrotik_info in MIKROTIK_INFO:
        rsc_file, backup_file = backup_mikrotik(mikrotik_info)
        
        # Cistenie lokalneho adresara
        clean_local_directory(LOCAL_DIRECTORY, '.rsc', 5)
        clean_local_directory(LOCAL_DIRECTORY, '.backup', 5)
        
        if rsc_file:
            # Ziskanie cisteho nazvu suboru (bez cesty) pre nahravanie
            local_rsc_filename = os.path.basename(rsc_file)
            local_backup_filename = os.path.basename(backup_file)
            
            # Nahrat .rsc subor na FTP
            upload_to_ftp(f'{LOCAL_DIRECTORY}/{local_rsc_filename}', local_rsc_filename)
            
            # Nahrat .backup subor na FTP
            upload_to_ftp(f'{LOCAL_DIRECTORY}/{local_backup_filename}', local_backup_filename)

            # Cistenie FTP adresara
            with FTP(FTP_INFO["server"]) as ftp:
                ftp.login(user=FTP_INFO["username"], passwd=FTP_INFO["password"])
                clean_ftp_directory(ftp, FTP_INFO["directory"], '.rsc', 5)
                clean_ftp_directory(ftp, FTP_INFO["directory"], '.backup', 5)
