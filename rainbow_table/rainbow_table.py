import rainbowtables as rt
address_hash = 'C:\\Users\\mashadservice\\Desktop\\uni\\lesson\\networkSecurity\\project\\2\\web_app\\users.txt'
address_salt_hash = 'C:\\Users\\mashadservice\\Desktop\\uni\\lesson\\networkSecurity\\project\\2\\web_app\\s_users.txt'

rt.set_directory("/", full_path=False)
rt.set_filename("demo_table")
rt.create_file()

# Generate the passwords
lettersLower = 'abcdefghijklmnopqrstuvwxyz'
numbers = "0123456789"
charset = lettersLower + numbers
pass_len = 4
passwords = []
different_chars_cnt = len(charset)
for i in range(different_chars_cnt ** pass_len):
    word = ""
    for j in range(pass_len):
        word = charset[i % different_chars_cnt] + word
        i //= different_chars_cnt
    passwords.append(word)

with open("password_list.txt", "w") as file:
    for password in passwords:
        file.write(f"{password}\n")

rt.insert("password_list.txt", "md5", wordlist_encoding="utf-8", display_progress=True, compression=True)
print('**** Processing Hashed Passwords ****')
with open(address_hash, 'r') as file:
    for line in file:
        line = line.strip()
        users_info = line.split(',')
        lookup = rt.search(
            users_info[2],
            "demo_table",
            full_path=False,
            time_took=True,
            compression=True)

        if lookup:
            print("Decrypted Hash : ", lookup[0])
        else:
            print("Decrypted Hash Not Found")

print('**** Processing Hashed using Salt and Pepper Passwords ****')
with open(address_salt_hash, 'r') as file:
    for line in file:
        line = line.strip()
        users_info = line.split(',')
        lookup = rt.search(
            users_info[2],
            "demo_table",
            full_path=False,
            time_took=True,
            compression=True)

        if lookup:
            print("Decrypted Hash using Salt and Pepper: ", lookup[0])
        else:
            print("Decrypted Hash using Salt and Pepper Not Found")