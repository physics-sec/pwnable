
def egcd(a, b): 
	x,y, u,v = 0,1, 1,0 
	while a != 0: 
		q, r = b//a, b%a 
		m, n = x-u*q, y-v*q 
		b,a, x,y, u,v = a,r, u,v, m,n 
		gcd = b 
	return gcd, x, y 

def main():

	p = 1090660992520643446103273789680343
	q = 1162435056374824133712043309728653
	e = 65537

	# compute n
	n = p * q

	# Compute phi(n)
	phi = (p - 1) * (q - 1)

	# Compute modular inverse of e
	gcd, a, b = egcd(e, phi)
	d = a
	print(d)

if __name__ == '__main__':
	main()
