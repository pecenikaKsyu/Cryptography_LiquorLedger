import string

alphabets = string.ascii_lowercase + string.ascii_lowercase

MyText = list(input('Type your text: \n').lower())

action = input(
    'enter encrypt to ENCRYPT, decrypt to DECRYPT, exit to EXIT the program \n').lower()

key = int(input('enter your shift number from 1 to 25: \n'))

end_program = False

while not end_program:
    if action == 'encrypt':
        for i in range(len(MyText)):
            if MyText[i] == ' ':
                MyText[i] = ' '
            else:
                new_letter = alphabets.index(MyText[i]) + key
                MyText[i] = alphabets[new_letter]
        print(''.join(map(str, MyText)))
        end_program = True
    elif action == 'decrypt':
        for i in range(len(MyText)):
            if MyText[i] == ' ':
                MyText[i] = ' '
            else:
                new_letter = alphabets.index(MyText[i]) - key
                MyText[i] = alphabets[new_letter]
        print(''.join(map(str, MyText)))
        end_program = True
    else:
        decide = input(
            'invalid entry, try again Y for YES, N for NO: \n').lower()
        if decide == 'y':
            MyText = list(input('enter your text: \n').lower())
            action = input(
                'enter encrypt to ENCRYPT, decrypt to DECRYPT, exit to EXIT the program \n').lower()
            key = int(input('enter your shift number from 1 to 25: \n'))
        else: 
            end_program = True