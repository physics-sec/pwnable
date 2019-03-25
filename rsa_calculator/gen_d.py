import sys

def egcd(a, b): 
	x,y, u,v = 0,1, 1,0 
	while a != 0: 
		q, r = b//a, b%a 
		m, n = x-u*q, y-v*q 
		b,a, x,y, u,v = a,r, u,v, m,n 
		gcd = b 
	return gcd, x, y 

def main():

	if len(sys.argv) == 3:
		p = int(sys.argv[1]) # 101
		q = int(sys.argv[2]) # 163
	else:
		p = 101
		q = 163
	print('p: ' + str(p))
	print('q: ' + str(q))
	if p * q < 256:
		sys.eixt('p * q debe ser mayor que 256')
	e = 65537
	e = 257
	print('e: ' + str(e))

	# compute n
	n = p * q

	# Compute phi(n)
	phi = (p - 1) * (q - 1)
	#rint('phi:' + str(phi))

	# Compute modular inverse of e
	gcd, a, b = egcd(e, phi)
	d = a

	# en el codigo da 0x01fbd521 por alguna razon...
	if (e * d) % phi != 1:
		print('(e * d) % phi = ' + str((e * d) % phi))

	#if e < phi:
	#	print('e < phi')
	#if d < phi:
	#	print('d < phi')

	print('d: ' + str(d))

if __name__ == '__main__':
	#if len(sys.argv) != 3:
	#	sys.exit('p y q como argumentos')
	main()
