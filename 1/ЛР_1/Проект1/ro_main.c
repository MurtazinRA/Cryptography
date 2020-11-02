#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <limits.h>
#include <math.h>
#include <stdint.h>
#include <locale.h>
//#pragma comment(linker, "/STACK:100000000")

#define BLOCK_SIZE 1

#ifndef uint64_t
# define uint64_t unsigned long long
#endif

uint64_t prostoe_chislo(void);
int64_t legendre_sym(int64_t a, int64_t p);
int64_t jacobi_sym(int64_t a, int64_t n);
int64_t jacobi_sym2(int64_t a, int64_t p);
uint64_t get_c(uint64_t p, uint64_t q);
uint64_t get_s(uint64_t p, uint64_t q, uint64_t c, uint64_t n);
uint64_t get_d(uint64_t m);
uint64_t get_e(uint64_t d, uint64_t m);
uint64_t gcd(uint64_t a, uint64_t b);
uint64_t xfd(uint64_t E, uint64_t n, uint64_t e, uint64_t c, uint64_t s, uint64_t num);
uint64_t X(uint64_t i, uint64_t a);
uint64_t Y(uint64_t i, uint64_t a, uint64_t b);
uint64_t cipher(char w, char *b1, char *b2, uint64_t n, uint64_t e, uint64_t c, uint64_t s);
uint64_t decipher(char E, char *b1, char *b2, uint64_t n, uint64_t e, uint64_t c, uint64_t s, uint64_t p, uint64_t q, uint64_t m, uint64_t d);
void generate_keys();
void fill(char * buf, uint64_t num);
uint64_t fill_read(char * buf, uint64_t num);





int main()
{
	setlocale(LC_ALL, "Rus");
	printf("%s\n", "Williams System");
	printf("%s\n", "Press e to encrypt, d to decrypt, g to generate keys");
	char mode;
	scanf("%c", &mode);
	while (!((mode == 'e') || (mode == 'E') || (mode == 'd') || (mode == 'D') || (mode == 'g') || (mode == 'G')))
	{
		printf("%s\n", "Please, press e to encrypt, d to decrypt, g to generate keys");
		scanf("%c", &mode);
	}
	if ((mode == 'g') || (mode == 'G'))
	{
		generate_keys();
		printf("%s\n", "Генерация ключей завершена");
	}
	else if ((mode == 'e') || (mode == 'E'))
	{
		if (encrypt() == -1)
		{
			printf("%s\n", "Error opening file");
			return 0;
		}
		printf("%s\n", "Шифрование завершено");
	}
	else if ((mode == 'd') || (mode == 'd'))
	{
		if (decrypt() == -1)
		{
			printf("%s\n", "Error opening file");
			return 0;
		}
		printf("%s\n", "Дешифрование завершено");
	}
	
	getchar();
	return 0;
	
}

void generate_keys()
{
	srand(time(NULL));
	uint64_t x = legendre_sym(271, 2343);
	uint64_t y = jacobi_sym2((uint64_t)-1, (uint64_t)143);
	uint64_t z = jacobi_sym2((uint64_t)4686, (uint64_t)4686);

	//int y = jacobi_sym()

	//printf("Hello world\n");
	uint64_t p = prostoe_chislo();
	uint64_t q = prostoe_chislo();
	uint64_t n = p * q;
	uint64_t c = get_c(p, q);
	uint64_t s = get_s(p, q, c, n);
	uint64_t m = (p - legendre_sym(c, p)) * (q - legendre_sym(c, q)) / 4;
	uint64_t d = get_d(m);
	uint64_t obr = inverse(d, m);
	if (obr < 0)
	{
		obr += m;
	}
	uint64_t e = ((m + 1) / 2 * obr) % m;

	unsigned char * buffer = (unsigned char*)malloc(sizeof(unsigned char) * sizeof(uint64_t));
	FILE *public_key_file;
	char name_in0[] = "public_key.bin";
	public_key_file = fopen(name_in0, "wb");
	
	fill(buffer, n);
	fwrite(buffer, sizeof(n), 1, public_key_file);
	fill(buffer, e);
	fwrite(buffer, sizeof(e), 1, public_key_file);
	fill(buffer, c);
	fwrite(buffer, sizeof(c), 1, public_key_file);
	fill(buffer, s);
	fwrite(buffer, sizeof(s), 1, public_key_file);
	fclose(public_key_file);

	FILE *private_key_file;
	char name_in00[] = "private_key.bin";
	private_key_file = fopen(name_in00, "wb");
	fill(buffer, p);
	fwrite(buffer, sizeof(p), 1, private_key_file);
	fill(buffer, q);
	fwrite(buffer, sizeof(q), 1, private_key_file);
	fill(buffer, m);
	fwrite(buffer, sizeof(m), 1, private_key_file);
	fill(buffer, d);
	fwrite(buffer, sizeof(d), 1, private_key_file);
	fclose(private_key_file);

	//int e = find_e(d, (m + 1)/2, m);
}

void fill(unsigned char * buf, uint64_t num)
{
	for (int i = 0; i < (sizeof(char) * sizeof(uint64_t)); i++)
	{
		buf[i] = num % 0x100;
		num /= 0x100;
	}
}

uint64_t fill_read(unsigned char * buf)
{
	uint64_t num = 0;
	char c = 0;
	for (int i = 0; i < (sizeof(char) * sizeof(uint64_t)); i++)
	{
		c = buf[i];
		num += buf[i] << (8 * i);
	}
	return num;
}

int encrypt()
{
	unsigned char * buffer = (unsigned char*)malloc(sizeof(unsigned char) * sizeof(uint64_t));
	//Получение публичных ключей
	uint64_t n = 0;
	uint64_t e = 0;
	uint64_t c = 0;
	uint64_t s = 0;
	uint64_t num = 0;


	FILE *public_key_file;
	char name_in0[] = "public_key.bin";
	if ((public_key_file = fopen(name_in0, "rb")) == NULL)
	{
		printf("Не удалось открыть файл с публичным ключом");
		getchar();
		return -1;
	}
	else
	{
		public_key_file = fopen(name_in0, "rb");
		fread(buffer, sizeof(n), 1, public_key_file);
		n = fill_read(buffer);
		fread(buffer, sizeof(e), 1, public_key_file);
		e = fill_read(buffer);
		fread(buffer, sizeof(c), 1, public_key_file);
		c = fill_read(buffer);
		fread(buffer, sizeof(s), 1, public_key_file);
		s = fill_read(buffer);
		fclose(public_key_file);
	}
	
	// Открытие входного и выходного файлов
	FILE *input;
	char name_in1[] = "in.txt";
	FILE *output;
	char name_in2[] = "encrypted.bin";
	if (((input = fopen(name_in1, "rb")) == NULL) || ((output = fopen(name_in2, "wb")) == NULL))
	{
		printf("Не удалось открыть файл");
		getchar();
		return -1;
	}
	else
	{
		// Если файлы открылись, то шифруем побайтово
		//char * buffer;
		int result;
		uint64_t block;
		char b1;
		char b2;
		while (1)
		{
			buffer = (unsigned char*)malloc(1 * (BLOCK_SIZE + 1));
			result = fread(buffer, 1, BLOCK_SIZE, input);
			if (!result)
			{
				break;
			}
			block = 0;
			for (int i = 0; i < BLOCK_SIZE; i++)
			{
				block += buffer[i] << (i * 8);
			}
			// предполагается длина блока в 1 байт
			block = cipher(block, &b1, &b2, n, e, c, s, num);
			buffer[0] = block;
			buffer[1] = b1;
			buffer[2] = b2;
			fwrite(buffer, 1, (BLOCK_SIZE + 2), output);
			num++;
		}
	}
	return 0;
}

int decrypt()
{
	//Получение публичных ключей
	unsigned char * buffer = (unsigned char*)malloc(sizeof(unsigned char) * sizeof(uint64_t));
	unsigned char * buf_b = (unsigned char*)malloc(sizeof(unsigned char) * 1);
	uint64_t n;
	uint64_t e;
	uint64_t c;
	uint64_t s;
	uint64_t num = 0;

	FILE *public_key_file;
	char name_in0[] = "public_key.bin";
	if ((public_key_file = fopen(name_in0, "rb")) == NULL)
	{
		printf("Не удалось открыть файл с публичным ключом");
		getchar();
		return -1;
	}
	else
	{
		public_key_file = fopen(name_in0, "rb");
		fread(buffer, sizeof(n), 1, public_key_file);
		n = fill_read(buffer);
		fread(buffer, sizeof(e), 1, public_key_file);
		e = fill_read(buffer);
		fread(buffer, sizeof(c), 1, public_key_file);
		c = fill_read(buffer);
		fread(buffer, sizeof(s), 1, public_key_file);
		s = fill_read(buffer);
		fclose(public_key_file);
	}

	//Получение приватных ключей
	uint64_t p;
	uint64_t q;
	uint64_t m;
	uint64_t d;

	
	FILE *private_key_file;
	char name_in00[] = "private_key.bin";
	if ((private_key_file = fopen(name_in00, "rb")) == NULL)
	{
		printf("Не удалось открыть файл с приватным ключом");
		getchar();
		return -1;
	}
	else
	{
		private_key_file = fopen(name_in00, "rb");
		fread(buffer, sizeof(p), 1, public_key_file);
		p = fill_read(buffer);
		fread(buffer, sizeof(q), 1, public_key_file);
		q = fill_read(buffer);
		fread(buffer, sizeof(m), 1, public_key_file);
		m = fill_read(buffer);
		fread(buffer, sizeof(d), 1, public_key_file);
		d = fill_read(buffer);
		fclose(public_key_file);
	}

	//Читаем побайтово из файла, дешифруем и пишем в файл вывода
	FILE *input;
	char name_in1[] = "encrypted.bin";
	FILE *output;
	char name_in2[] = "decrypted.txt";
	if (((input = fopen(name_in1, "rb")) == NULL) || ((output = fopen(name_in2, "wb")) == NULL))
	{
		printf("Не удалось открыть файл");
		getchar();
		return -1;
	}
	else
	{
		//char * buffer;
		int result;
		uint64_t block;
		char b1 = 0;
		char b2 = 0;
		while (1)
		{
			buffer = (unsigned char*)malloc(1 * BLOCK_SIZE + 2);
			result = fread(buffer, 1, (BLOCK_SIZE + 2), input);
			if (!result)
			{
				break;
			}
			block = 0;
			for (int i = 0; i < BLOCK_SIZE; i++)
			{
				block += buffer[i] << (i * 8);
			}
			/*fread(buf_b, 1, 1, input);
			b1 = buf_b[0];
			fread(buf_b, 1, 1, input);
			b2 = buf_b[0];*/

			b1 = buffer[1];
			b2 = buffer[2];

			// предполагается длина блока в 1 байт
			block = decipher(block, b1, b2, n, e, c, s, p, q, m, d, num);
			buffer[0] = block;
			fwrite(buffer, 1, BLOCK_SIZE, output);
			num++;
		}

	}
}



uint64_t cipher(unsigned char w, char *b1, char *b2, uint64_t n, uint64_t e, uint64_t c, uint64_t s, uint64_t num)
{
	w = (uint64_t)w;
	//uint64_t b1;
	//uint64_t b2;
	int ja = jacobi_sym(w*w - c, n);
	if (ja == 1)
		*b1 = 0;
	else if (ja == -1)
		*b1 = 1;
	
	uint64_t a_num = 0;
	uint64_t a_denom = 0;
	uint64_t b_num = 0;
	uint64_t b_denom = 0;
	if (*b1 == 1)
	{
		a_num = w*w + c;
		a_denom = w*w - c;
		b_num = 2*w;
		b_denom = w*w - c;
	}
	else
	{
		a_num = (w*w + c)*(s*s + c) + 4*c*s*w;
		a_denom = (w*w - c)*(s*s - c);
		b_num = 2*s*(w*w + c) + 2*w*(s*s + c);
		b_denom = (w*w - c)*(s*s - c);
	}

	uint64_t a = a_num*inverse(a_denom, n);
	uint64_t b = b_num*inverse(b_denom, n);

	if (a % 2 == 0)
	{
		*b2 = 0;
	}
	else
	{
		*b2 = 1;
	}

	uint64_t E = 0;
	E = xfd(w, n, e, c, s, num);
	if (E)
	{
		*b1 = E % 2;
		*b2 = (*b1 + 1) % 2;
		return E;
	}
	E = (X(e, a)*inverse(Y(e, a, b), n)) % n;
	return E;


}

uint64_t X(uint64_t i, uint64_t a)
{
	if (i == 1)
		return a;
	else if (i % 2 == 0)
	{
		return (2 * X(i / 2, a)*X(i / 2, a) - 1);
	}
	else
	{
		return (2 * X(i / 2, a) *X((i - 1) / 2 + 1, a) - a);
	}
}

uint64_t Y(uint64_t i, uint64_t a, uint64_t b)
{
	if (i == 1)
		return b;
	else if (i % 2 == 0)
	{
		return 2 * X(i / 2, a)*Y(i / 2, a, b);
	}
	else
	{
		return (2*X(i/2, a)*Y((i-1)/2 + 1, a, b) - b);
	}
}

uint64_t decipher(unsigned char E, char *b1, char *b2, uint64_t n, uint64_t e, uint64_t c, uint64_t s, uint64_t p, uint64_t q, uint64_t m, uint64_t d, uint64_t num)
{
	E = (uint64_t)E;
	//Коэффициенты для alpha в степени 2e
	//uint64_t alpha_2e
	uint64_t a_num = E*E + c;
	uint64_t a_denom = E*E - c;
	uint64_t b_num = 2 * E;
	uint64_t b_denom = E*E - c;

	uint64_t a = a_num*inverse(a_denom, n);
	uint64_t b = b_num*inverse(b_denom, n);

	E = xfd(E, n, e, c, s, num);
	if (E)
	{
		return E;
	}
	uint64_t Xd = X(d, a);
	uint64_t Yd = Y(d, a, b);

	uint64_t a_shtrih;

	uint64_t w = 0;
	w = xfd(E, n, e, c, s, num);
	if (w)
	{
		*b1 = E % 2;
		*b2 = (*b1 + 1) % 2;
		return w;
	}
	if (!(*b1))
	{

	}



}

uint64_t xfd(uint64_t E, uint64_t n, uint64_t e, uint64_t c, uint64_t s, uint64_t num)
{
	num %= 12;
	uint64_t a0;
	uint64_t a;
	uint64_t b;
	unsigned char * buffer = (unsigned char*)malloc(12);
	if (num < 4)
	{
		//a0 = (uint64_t)(n >> (8 * num));
		return (E ^ (unsigned char)(n >> (8 * num)));
		//a0 = (uint64_t)pow(2, 8 * num);
		//a = n % a0;
		//b = a >> (8 * num);
		//return E ^ (uint64_t)((n % (uint64_t)(pow(2, 8 * num))) >> (8 * num));
	}
	else if ((num >= 4) && (num < 8))
		return (E ^ (unsigned char)(e >> (8 * (num - 4))));
		//return E ^ (uint64_t)((n % (uint64_t)(pow(2, 8 * (num - 4)))) >> (8 * (num - 4)));
	else if ((num >= 8) && (num < 10))
		return (E ^ (unsigned char)(c >> (8 * (num - 8))));
		//return E ^ (uint64_t)((n % (uint64_t)(pow(2, 8 * (num - 8)))) >> (8 * (num - 8)));
	else if ((num >= 10) && (num < 12))
		return (E ^ (unsigned char)(s >> (8 * (num - 10))));
		//return E ^ (uint64_t)((n % (uint64_t)(pow(2, 8 * (num - 10)))) >> (8 * (num - 8)));
	//for (int i = 0; i < 12; i++)
	//{
	//	if (i < 4)
	//		buffer[i] = n % 

	//}
	//return ((E % 0x100) ^ (n % 0x100));
}

uint64_t get_c(int64_t p, int64_t q)
{
	uint64_t a = 3;
	uint64_t b = 1000;
	//srand(time(NULL));
	uint64_t c = 0;
	uint64_t sigma_p = 0;
	uint64_t sigma_q = 0;
	//int ostatok_p = 0;
	//int ostatok_q = 0;
	//int s1 = 0;
	//int s2 = 0;
	while (1)
	{
		//s1, s2, ostatok_p, ostatok_q = 0;
		printf("didn't get\n");
		//c = a + rand()%(b - a + 1);
		c = rand() % (RAND_MAX - a + 1);
		sigma_p = legendre_sym(c, p);
		sigma_q = legendre_sym(c, q);
		//ostatok_p = -p % 4;
		//ostatok_q = -q % 4;
		if ((((-p - sigma_p) % 4) == 0) && (((-q - sigma_q) % 4) == 0))
		{
			break;
		}
	}
	//while (!((legendre_sym(c, p) == -p % 4) && (legendre_sym(c, q) == -q % 4)));
	//printf("Got it!!\n");
	return c;
}

uint64_t get_s(uint64_t p, uint64_t q, uint64_t c, uint64_t n)
{
	srand(time(NULL));
	uint64_t s = 0;
	do
	{
		s = rand();
		//if (jacobi_sym2(s*s - c, n) == -1)
		//{
		//	s = 2;
		//}
		//if (gcd(s, n) == 1)
		//{
		//	s = 3;
		//}
	} while (!((jacobi_sym2(s*s - c, n) == -1) && (gcd(s, n) == 1)));
	return c;
}

uint64_t get_d(uint64_t m)
{
	uint64_t d = 0;
	while (1)
	{
		d = rand();
		if ((d > 1) && (gcd(d, m) == 1))
			break;
	}
	return d;
}

uint64_t get_e(uint64_t d, uint64_t m)
{
	uint64_t e;
	uint64_t mm = (m + 1) / 2;
	uint64_t ost1 = 0;
	uint64_t ost2 = 0;
	while (1)
	{
		e = rand();
		ost1 = (d*e) % m;
		ost2 = mm % m;
	}
	return e;
}

void extended_euclid(uint64_t a, uint64_t b, uint64_t *x, uint64_t *y, uint64_t *d)
/* вычисление a * *x + b * *y = gcd(a, b) = *d */
{
	uint64_t q, r, x1, x2, y1, y2;
	if (b == 0) {
		*d = a, *x = 1, *y = 0;
		return;
	}

	x2 = 1, x1 = 0, y2 = 0, y1 = 1;
	while (b > 0) {
		q = a / b, r = a - q * b;
		*x = x2 - q * x1, *y = y2 - q * y1;
		a = b, b = r;
		x2 = x1, x1 = *x, y2 = y1, y1 = *y;
	}

	*d = a, *x = x2, *y = y2;
}

long inverse(uint64_t a, uint64_t n)
/* вычисление инверсии модуля n */
{
	uint64_t d, x, y;
	extended_euclid(a, n, &x, &y, &d);
	if (d == 1) return x;
	return 0;
}




uint64_t find_e(uint64_t a, uint64_t b, uint64_t n)
{
	//int x = a;
	//if (x > n) 
	//	x = x % n;
	//int e = x;
	//int i;
	//for (i = 1; i < b; i++)
	//{
	//	e = e * x;
	//	if (e > n)
	//	{
	//		e = e % n;
	//	}
	//}
	//return e;


	//int x, y;
	//int g = gcdex(a, m, x, y);
	//x = (x % m + m) % m;
	//cout << x;
	//x = (x % m + m) % m;

}

int f_eiler(int n) 
{
	int result = n;
	for (int i = 2; i*i <= n; ++i)
		if (n % i == 0) 
		{
			while (n % i == 0)
				n /= i;
			result -= result / i;
		}
	if (n > 1)
		result -= result / n;
	return result;
}


uint64_t prostoe_chislo(void)
{
	//uint64_t x = INT_MAX;
	//uint64_t y = LLONG_MAX;

	//printf("%d\n", RAND_MAX);
	//printf("%d\n", INT_MAX);
	//printf("%d\n", ULONG_MAX);
	//printf("%d\n", LLONG_MAX);

	//printf("%d\n", x);
	//printf("%lld\n", y);


	uint64_t a;
	//static time_t tval = time(0);
	//tval += 10;
	//printf("tval = %d\n\n", tval);
	//srand(tval);
	//srand(time(NULL));
	while (1)
	{
		uint64_t z = 0;
		uint64_t kol = 0;
		do
		{
			a = rand();
		} while (a < 3);

		//printf("%d\n",a);
		for (uint64_t i = 2; i < a; i++)
		{
			if (a % i == 1)
				continue;
			if (a % i == 0)
			{
				z = 1;
				break;
			}
		}
		if (z == 0)
		{
			printf("%lld - chislo prostoe\n", a);
			break;
		}
		else
			printf("%lld - chislo sostavnoe\n", a);
	}
	return a;
}



/*
int is_prime(unsigned long n) {
for(unsigned long i = 3; i * i <= n; ++i)
if( !(n % i)) return 0;
return 1;
}
*/

//int legendre_symbol(int a, int p) {
//	a %= p;
//	if (a == 0)
//	{
//		return 0;
//	}
//	if (p == 3)
//	{
//		int ls_3[3] = { 0, 1, -1 }; // legendre_symbol(a, 3)
//		return ls_3[a];
//	}
//	return is_residue(a, p) ? 1 : -1;
//}

//int is_residue(const int a, const int p) {
//	for (int x = 1; x < p; ++x) {
//		if (int64_t(x * x) % p == a)
//			return 1;
//	}
//	return 0;
//}

uint64_t get_multiplier(uint64_t N)
{

	for (uint64_t i = 2; i*i <= N; i++)
	{
		if (N%i == 0)
		{
			return i;
		}
	}
	return 0;
}

uint64_t gcd(uint64_t a, uint64_t b)
{
	return b ? gcd(b, a % b) : a;
}

int64_t legendre_sym(int64_t a, int64_t p)
{
	if (a == 0)
	{
		return 0;
	}
	else if (a == 1)
	{
		return 1;
	}
	else if ((a % 2) == 0)
	{
		return (legendre_sym(a / 2, p) * pow(-1, (p*p - 1) / 8));
	}
	else if (a % 2 == 1)
	{
		return (legendre_sym(p % a, a) * pow(-1, (a - 1)*(p - 1) / 4));
	}

}

int64_t jacobi_sym2(int64_t a, int64_t p)
{
	int64_t res = 1;
	int64_t multiplier = get_multiplier(p);
	while (multiplier)
	{
		res *= legendre_sym(a, multiplier);
		p /= multiplier;
		multiplier = 0;
	}
	res *= legendre_sym(a, p);
}

int64_t jacobi_sym(int64_t a, int64_t n)
{

	if (a < 0)
	{
		return (jacobi_sym(-a, n) * pow(-1, (n - 1) / 2));
	}
	else if (a % 2 == 0)
	{
		return (jacobi_sym(a / 2, n) * pow(-1, (n*n - 1) / 8));
	}
	else if (a == 1)
	{
		return 1;
	}
	else if (a < n)
	{
		return (pow(-1, (a - 1)*(n - 1) / 4) * jacobi_sym(n, a));
	}
	else
	{
		return (a % n, n);
	}
}



//int gcdex_b(int a, int b, int x, int y) 
//{
//	if (a == 0) 
//	{
//		x = 0; y = 1;
//		return b;
//	}
//	int x1, y1;
//	int d = gcd(b%a, a, x1, y1);
//	x = y1 - (b / a) * x1;
//	y = x1;
//	return d;
//}
//
//int gcdex_x(int a, int b, int x, int y)
//{
//	if (a == 0)
//	{
//		x = 0; y = 1;
//		return b;
//	}
//	int x1, y1;
//	int d = gcd(b%a, a, x1, y1);
//	x = y1 - (b / a) * x1;
//	y = x1;
//	return x;
//}


//int gcd(int a, int b)
//{
//	int c = 0;
//	if(a < b)
//	{  
//		c = a;
//		a = b;
//		b = c; 
//	}
//	while (b) 
//	{
//		c = b;
//		b = a % b;
//		a = c;
//	}
//	return a;
//}



/*int N = 998;
for (int i = 2; i*i <= N; i++) {
if (N%i == 0) {
printf("%d^", i);
int k = 0;
for (k = 0; N%i == 0; k++) {
N /= i;
}
printf("%d ", k);
}
}
if (N > 1) printf("%d ", N);
printf("\n");*/


