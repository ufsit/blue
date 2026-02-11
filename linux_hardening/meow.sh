#!/bin/sh
# v8
# Requires: openssl ssh sshpass wamerican-small

# Goal: repeated password rolling for Linux systems

# initAdmin() is a simple text generator for the start of comp when one admin has the same password
#       across the network. It will output the following content in the format: USER IP PASSWORD.
#       For subsequent runs, this function must be ignored, which will be the default case.
#       RETURNS [-- adminUser.txt --]: admin user and password for every host; MUST be up-to-date

# genPasswd() generates passphrases from a standard dictionary in *nix systems:
#       3 random words, "0" sepearated

# genUserList() loops through [adminUser.txt] to login and extract /etc/passwd for a list of users
#       RETURNS [-- users.txt --]       list of users in every host

# assignPasswd() assigns passwords to every user with the following rules:
#       * nonAdmin users get the same passwords if they exist across different machines
#       * Admin users get different passwords
#       RETURNS [-- clear.txt --]        USER IP CLEAR_TEXT_PASSWORD, all users, source of truth
#               [-- passwdHashes.txt --] USER IP HASHED_PASSWORD, all users, source of truth
#               [-- userHashes.txt --]   USER IP HASHED_PASSWORD, non-admin users
#               [-- adminHashes.txt --]  USER IP HASHED_PASSWORD, admin users

# confirmRoll() rolls passwords in two waves:
#       1. non-admin users, using userHashes.txt
#               * Admin user logs in, once per user, and 'sed's /etc/shadow
#       2. admin users, using adminHashes.txt
#               * Admin user logs in, changes its own password
#       On each loop, an OK or FAIL is returned
#       UPDATES [-- adminUser.txt --]   

initAdmin() {
        echo -n 'First roll? [y/N]:\t'
        read isFirstRoll
        case "$isFirstRoll" in
                y) ;;
                *) return ;;
        esac     

        echo -n "Admin:\t\t\t"
        read -r adminUser
        echo -n "Password:\t\t"
        read -r adminPass
        while :; do
                rm -f adminUser.txt
                while :; do
                        echo -n "IP Address (x to stop): "
                        read -r ip;
                        case "$ip" in
                                x) break ;;
                                *) echo $adminUser $ip $adminPass >> adminUser.txt ;;
                        esac
                done
                
                echo "\n----- adminUser.txt Contents -----"
                cat adminUser.txt
                echo -n '\nConfirm? [y/N]: '
                read isInitAdminGood
                case "$isInitAdminGood" in
                        y) break ;;
                        *) ;;
                esac
        done
}

genPasswd() {
        grep -E '^[a-z]{3,}$' /usr/share/dict/words | shuf -n 3 | paste -sd '0' -
}

genUserList() {
        rm -f users.txt
        while read -r adminUser ip adminPass; do
                printf "Grabbing users from %-15s with %s:%s\n" "$ip" "$adminUser" "$adminPass" 
                sshpass -p "$adminPass" ssh -n -o StrictHostKeyChecking=no "${adminUser}@${ip}" "grep -Ev '^#|/usr/bin/nologin|/sbin/nologin|/bin/false|sync|bta|black' /etc/passwd | awk -F: '{print \$1\" $ip\"}'" >> users.txt
        done < adminUser.txt
}

assignPasswd() {
        rm -f clear.txt passwdHashes.txt userHashes.txt adminHashes.txt
        adminUser="$(awk '{print $1; exit}' adminUser.txt)"
        
        while read -r user ip; do
                if [ "$user" != "$adminUser" ] && [ "$user" != "root" ]; then
                        # If password already assigned to user, use previous
                        if grep -q -s -e "^$user " clear.txt; then
                                pass=$(grep -e "^$user " clear.txt | head -n 1 | awk '{print $3}')
                        else
                                pass="$(genPasswd)"
                        fi
                else
                        pass="$(genPasswd)" 
                fi

                # For PCR purposes
                echo "$user $ip $pass" >> clear.txt

                # To modify password
                hashPass=$(openssl passwd -6 "$pass")
                echo "$user $ip $hashPass" >> passwdHashes.txt
        done < users.txt
        
        # Making clear.txt pretty
        column -t clear.txt | awk 'NR>1 && $2!=prev {print ""} {print; prev=$2}' > clear.tmp
        mv clear.tmp clear.txt
        

        grep -v -E "$adminUser" passwdHashes.txt >> userHashes.txt
        grep -E "$adminUser" passwdHashes.txt >> adminHashes.txt
}

confirmRoll() {
        echo "\n----- New Passwords -----"
        cat clear.txt
        echo -n "\nExecute? [y/N] "
        read -r confirm
        case $confirm in
                y) ;;
                *) exit ;;
        esac
        
        echo "----- User roll -----"
        while read -r user ip hash; do
                adminUser="$(awk '{print $1; exit}' adminUser.txt)"
                adminPass="$(grep "$ip" adminUser.txt | awk '{print $3}')"
                userPass="$(grep "$user" clear.txt | grep "$ip$" | awk '{print $3}')"
                
                # Escaping sensitive chars
                safe_hash=$(printf '%s\n' "$hash" | sed 's/\$/\\$/g')
                
                printf "Editing %-12s @%-15s with %s:%-35s " "$user" "$ip" "$adminUser" "$adminPass"
                if sshpass -p "$adminPass" ssh -n -o StrictHostKeyChecking=no "${adminUser}@${ip}" "sudo sed -i \"s|^$user:[^:]*:|$user:$safe_hash:|\" /etc/shadow" 2>/dev/null; then
                        echo OK
                else
                        echo FAIL
                fi                
        done < userHashes.txt

        echo "----- Admin Roll -----"
        while read -r user ip hash; do
                oldPass="$(grep "$ip" adminUser.txt | awk '{print $3}')"

                # Escaping $ chars
                safe_hash=$(printf '%s\n' "$hash" | sed 's/\$/\\$/g')
                
                printf "Editing %-12s @%-15s with %s:%-35s " "$user" "$ip" "$adminUser" "$oldPass"
                if sshpass -p "$oldPass" ssh -n -o StrictHostKeyChecking=no "${user}@${ip}" "sudo sed -i \"s|^$user:[^:]*:|$user:$safe_hash:|\" /etc/shadow" 2>/dev/null; then
                        echo OK
                else
                        echo FAIL
                fi
        done < adminHashes.txt
        
        # Updating adminUser passwords
        grep $adminUser clear.txt | awk '{ print $1, $2, $3 }' > adminUser.tmp
        mv adminUser.tmp adminUser.txt
        
        # For PCR
        echo "\n----- New Admin Passwords -----"
        cat adminUser.txt | column -t
}

initAdmin
genUserList
assignPasswd
confirmRoll