#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <iostream>
#include <sstream>
#include <map>
#include <NTL/ZZ.h>
#include "FHE.h"
#include "timing.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include "rapidxml-1.13/rapidxml.hpp"
#include <fstream>
#include <sys/time.h>
#include <set>
#include <algorithm>


using namespace std;
using namespace rapidxml;

FHEcontext* context;
FHESecKey* secretKey;
FHEPubKey* publicKey;
EncryptedArray* ea;
ZZX G;




void init(long p_m, long p_p, long p_k, long p_l);
bool saveKeys(const char* file_context, const char* file_sk, const char* file_pk);
bool loadKeys(const char* file_context, const char* file_sk, const char* file_pk, unsigned long &m1, unsigned long &p1, unsigned long &r1);
Ctxt encryption(long a);
long decryption(Ctxt ct);
string ctxtToString(Ctxt ct);
Ctxt stringToCtxt(string str);
map<string, vector<long> > readXml(const char* file, string &title);
void encryptXml(map<string, vector<long> > mm, const char* f, string title, map<int, vector<string> > mmm);
map<string, vector<string> > readEncryptedXml(const char* file, string &title);
long convertScore(double score);
map<string, vector<long> > readReq(const char* f, string &cont, string &path);
void encryptReq(map<string, vector<long> > mm, const char* f, string title, string path, map<int, vector<string> > mmm);
map<string, vector<string> > readEncryptedReq(const char* file, string &path);
void listFiles( string path, vector<string> &vec );
void constructTableScores( int min, int max, int occ, int occZero);
vector<string> split(const string &s, char delim);
void listFiles( string path, vector<string> &vec );
map<int, vector<string> > readScoresTable( const char* path);
void constructTableHE( map<int, vector<string> > map);
void saveHE(const char* path, string value);
void encode(std::string& data);
map<string, vector<string> > search(string &path_req);
string getPathConcept(string title, string home);
map<int, vector<string> > sort(map<string, int> map_scores, int &max);
Ctxt getEncryptedScore(string score);
map<string, vector<long> > decryptResult(map<string, vector<string> > m);
map<int, string> trier(map<string, vector<long> > m, string path, vector<int> &vec);
vector<int> comaprer(string path_req, string path_doc);
vector<int> someVectors(vector<int> vec1, vector<int> vec2);
void updateXml(string path_doc, vector<string> list_docs, int percent, vector<string> list_zero);
vector<string> readListDocuments(string path);
inline bool ends_with(std::string const & value, std::string const & ending);
map<string, string> readEncryptedUser(const char* f);


int main() { 

	unsigned long m=4951, p=9001, k=80, L=8, r;
        struct timeval a, b; 
        int tab[] = {0, 0, 0, 0};
        vector<int> vec_res (tab, tab+4);
	
	
	bool ok = loadKeys("context", "sk", "pk", m, p, r);
	cout << "Keys OK ... " << endl;
        
        /*map<int, vector<string> > list_zero = readScoresTable( "Scores");
        cout << list_zero[0].size() << endl;
        vector<string> list_docs = readListDocuments("docs.txt");
        cout << list_docs.size() << endl ;
        vector<string> vect;
        listFiles("Concepts", vect);
        for (unsigned i=0; i<vect.size(); i++){
           string path = vect[i];
           if (ends_with(path, ".he")){
              cout << i << " - " ;
              updateXml(path, list_docs, 100, list_zero[0]);
           }
        }*/

        vector<string> vect;
        string path ;
        cout << "Enter the path of the Request (Try 'Req') : " ;
        cin >> path;
        listFiles(path.c_str(), vect);
        cout << vect.size() << endl;
        cout << "size = " << vect.size() << endl;

        gettimeofday(&a, NULL);
        unsigned long long t2 = 0;

        for (unsigned i=0; i<vect.size(); i++){

           gettimeofday(&a, NULL);
           
           string path = vect[i];
          // cout << i << " Req = " << path << endl;
           map<string, vector<string> > mm = search(path);
          // cout << "ok" << endl;
           if(!mm.empty()){
               map<string, vector<long> > mmm = decryptResult(mm); 
        //       cout << "ok" << endl;
               map<int, string> res = trier(mmm, path, vec_res);
          //     cout << "ok" << endl;
           }

          /* map<int, string>::iterator it;
           for(it=res.begin(); it!=res.end();it++)
          cout << it->first << " - " << it->second << " --> " << mmm[it->second][0] << " | " << mmm[it->second][1] << " | " << mmm[it->second][2] << endl;*/

         cout << "Result = " << vec_res[0] << " | " << vec_res[1] << " | " << vec_res[2] << " | " << vec_res[3] << endl;

          
           gettimeofday(&b, NULL);
           t2 += (b.tv_sec*1000LL + b.tv_usec/1000LL - a.tv_sec*1000LL - a.tv_usec/1000LL);
           printf("time for %d search(es) = %llu\n",i+1,  t2);
         
        }


        

       /* map<int, vector<string> > mmm = readScoresTable("Scores");
        string title, link;*/
       /* map<string, vector<long> > mm =readReq("Reqs/0", title, link);
        encryptReq(mm, "Reqs/0", title, link, mmm);*/
        


        //constructTableHE(mmm);
	

       /* vector<string> vect;
        string path = "/home/fate7/Documents/Programs/Index/" ;
        cout << "Enter the path of the collection : " ;
        cin >> path;
        listFiles(path.c_str(), vect);
        cout << vect.size() << endl;

        gettimeofday(&a, NULL);

        for (unsigned i=0; i<vect.size(); i++){
           
           string path = vect.at(i);
           cout << i << " - " << path << endl;

	   string title;

           map<string, vector<long> > mm =readReq(path.c_str(), title, link);

           if (mm.empty())
              continue;
	  
	   encryptReq(mm, path.c_str(), title, link, mmm);
	 

           if ((i+1) % 100 == 0){
              gettimeofday(&b, NULL);
              unsigned long long t2 = (b.tv_sec*1000LL + b.tv_usec/1000LL - a.tv_sec*1000LL - a.tv_usec/1000LL);
              printf("time fro %d documents = %llu\n",i+1,  t2);
           }
   
         }

         gettimeofday(&b, NULL);
         unsigned long long t2 = (b.tv_sec*1000LL + b.tv_usec/1000LL - a.tv_sec*1000LL - a.tv_usec/1000LL);
         printf("time documents = %llu\n", t2);*/



	return 0;

}

/*
   Init

*/

void init(long p_m, long p_p, long p_k, long p_l){

	printf("Start initialisation ... \n");
	long m=p_m, p=p_p, r=1;

	long K = p_k;
	long L = p_l;
	long c = 3;
	long d = 0;
	long s = 0;
	long chosen_m = 0;
	long w = 64;
	
	if (p_m==0)
		m = FindM(K, L, c, p, d, s, chosen_m, true);
	
	cout << m << endl;
	

	context = new FHEcontext(m, p, r);

	buildModChain(*context, L, c);

	secretKey = new FHESecKey(*context);
	publicKey = secretKey;
	secretKey->GenSecKey(w);
	addSome1DMatrices(*secretKey);	

	cout << "Generated key " << endl;

	G = context->alMod.getFactorsOverZZ()[0];	

	ea = new EncryptedArray(*context, G);

	
}

/*

	save

*/

bool saveKeys(const char* file_context, const char* file_sk, const char* file_pk){

	cout << "Start saving ...\n" ;

	FILE* f = fopen(file_context, "w");
	ostringstream oss;
	writeContextBase(oss, *context);
	oss << *context;
	string text = oss.str();
	fprintf(f, "%s", text.c_str());
	fclose(f);

	f = fopen(file_sk, "w");
	ostringstream oss2;
	oss2 << *secretKey;
	text = oss2.str();
	fprintf(f, "%s", text.c_str());
	fclose(f);

	f = fopen(file_pk, "w");
	ostringstream oss3;
	oss3 << *publicKey;
	text = oss3.str();
	fprintf(f, "%s", text.c_str());
	fclose(f);

	cout << "End saving ...\n" ;
	return true;
}

/*

	Load

*/

bool loadKeys(const char* file_context, const char* file_sk, const char* file_pk, unsigned long &m1, unsigned long &p1, unsigned long &r1){

	FILE* f3;
	string str="";
	char * line;
	size_t len = 0;
	ssize_t read;

	f3 = fopen(file_context, "r");
	if (f3){
		while (read=getline(&line, &len, f3)!=-1){
			string temp(line);
			str += temp;			
		}
			
		fclose(f3);		
	}
	
	istringstream iss;
	iss.str(str);
	vector<long> gens, ords;

	readContextBase(iss, m1, p1, r1, gens, ords);
	context = new FHEcontext(m1, p1, r1, gens, ords);
	iss>>*context;

	cout << "context done\n";

	secretKey = new FHESecKey(*context);
	str ="";

	f3 = fopen(file_sk, "r");
	if (f3){
		while (read=getline(&line, &len, f3)!=-1){
			string temp(line);
			str += temp;			
		}			
		fclose(f3);		
	}
	
	istringstream iss2;
	iss2.str(str);
	iss2>> *secretKey;

	cout << "sk done\n";

	publicKey = secretKey ;

	f3 = fopen(file_pk, "r");
	str = "";
	if (f3){
		while (read=getline(&line, &len, f3)!=-1){
			string temp(line);
			str += temp;
			
		}			
		fclose(f3);		
	}

	istringstream iss3;
	iss3.str(str);
	iss3>> *publicKey;

	cout << "pk done\n";

	G = context->alMod.getFactorsOverZZ()[0];	

	ea = new EncryptedArray(*context, G);

	return true;
}

/*

	Encryption (a, b)

*/

Ctxt encryption(long a){
	
	//cout << "Start encryption ...\n" ;

	vector<long> v1;
	v1.push_back(a);
	
	for (int i=1; i<ea->size(); i++)		
		v1.push_back(0);		
	
	Ctxt ct1(*publicKey);
	ea->encrypt(ct1, *publicKey, v1);
	//cout << "end encryption ...\n" ;
	return ct1;

}

/*

	Decryption (a, b)

*/

long decryption(Ctxt ct){
	vector<long> res;
	ea->decrypt(ct, *secretKey, res);
	return res[0];
}

string ctxtToString(Ctxt ct){
	ostringstream oss;
	oss << ct;
	return oss.str();
}

Ctxt stringToCtxt(string str){

	istringstream iss;
	Ctxt ct(*publicKey);
	iss.str(str);
	iss >> ct;

	return ct;
}

map<string, vector<long> > readXml(const char* f, string &title){
	map<string, vector<long> > m;
	string str;
	xml_document<> doc;
	//cout << "ok";
	ifstream file(f);
	//cout << "ok";
	stringstream buffer;
	buffer << file.rdbuf();
	file.close();
	string content(buffer.str());
        if (content.empty())
            return m;
	doc.parse<0>(&content[0]);
	xml_node<> *root = doc.first_node();
	title = root->first_attribute("libelle")->value();
	for (xml_node<> *node=root->first_node("Document"); node; node=node->next_sibling()){
		str = node->value();
                encode(str);
		vector<long> vec;
		vec.push_back(convertScore(strtod(node->first_attribute("score")->value(), NULL)));
		vec.push_back(strtod(node->first_attribute("occurence")->value(), NULL));
		m[str] = vec;
		
	}
	
	return m;
}

map<string, vector<long> > readReq(const char* f, string &cont, string &path){
	map<string, vector<long> > m;
	string str;
	xml_document<> doc;
	ifstream file(f);
	stringstream buffer;
	buffer << file.rdbuf();
	file.close();
	string content(buffer.str());
        try{
           doc.parse<0>(&content[0]);
        }
        catch(rapidxml::parse_error &e){
           return m;
        }
	xml_node<> *root = doc.first_node();
	cont = root->first_attribute("content")->value();
	path = root->first_attribute("path")->value();
        encode(cont); encode(path);
	for (xml_node<> *node=root->first_node("Concept"); node; node=node->next_sibling()){
		str = node->value();
		vector<long> vec;
		vec.push_back(convertScore(strtod(node->first_attribute("score")->value(), NULL)));
		vec.push_back(strtod(node->first_attribute("occurence")->value(), NULL));
		m[str] = vec;
		
	}
	
	return m;
}

void encryptXml(map<string, vector<long> > mm, const char* f, string title, map<int, vector<string> > map_s){
	string name = f; 
        //name = name.substr(name.find_last_of("/")+1); 
        name+= ".he";	
	//name = "Concepts.HE/"+name;
	//cout << name << endl;
	ofstream file(name.c_str());
	file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << endl;
	file << "<Concept libelle=\"" << title << "\">" << endl;
	map<string, vector<long> >::iterator im;
	for(im=mm.begin(); im!=mm.end(); im++){
                int rank = rand() % 10 + 1;
                string sc = map_s[(*im).second[0]][rank];
                rank = rand() % 10 + 1;
                string occ = map_s[(*im).second[1]][rank];
                file << "<Document score=\"" << sc << "\" occurence=\"" << occ <<"\">";
		file << (*im).first ;
		file << "</Document>" << endl;
	}
	file << "</Concept>" << endl;
	file.close();
}

void encryptReq(map<string, vector<long> > mm, const char* f, string title, string path, map<int, vector<string> > map_s){
	string name = f; name+= ".he" ;	
	ofstream file(name.c_str());
	file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << endl;
	file << "<Requete content=\"" << title << "\" path=\"" << path << "\">" << endl;
	map<string, vector<long> >::iterator im;
	for(im=mm.begin(); im!=mm.end(); im++){
                int rank = rand() % 10 + 1;
                string sc = map_s[(*im).second[0]][rank];
                rank = rand() % 10 + 1;
                string occ = map_s[(*im).second[1]][rank];
                file << "<Concept score=\"" << sc << "\" occurence=\"" << occ <<"\">";
		file << (*im).first ;
		file << "</Concept>" << endl;
	}
	file << "</Requete>" << endl;
	file.close();
}

map<string, vector<string> > readEncryptedXml(const char* f, string &title){
    map<string, vector<string> > m;
    int i = 0;
    xml_document<> doc;
    ifstream file(f);
    if (file){
       // cout << "ok" << endl;
	stringstream buffer;
	buffer << file.rdbuf();
	file.close();
	string content(buffer.str());
	doc.parse<0>(&content[0]);
	xml_node<> *root = doc.first_node();
	title = root->first_attribute("libelle")->value();
	for (xml_node<> *node=root->first_node("Document"); node; node=node->next_sibling()){
		string str1 = node->first_attribute("score")->value();
                string str2 = node->first_attribute("occurence")->value();
		string content = node->value();
		vector<string> vec;
		vec.push_back(str1);
		vec.push_back(str2);
		m[content] = vec;
            //    cout << ++i << content << endl;
		
	}
     }
	
     return m;
}

map<string, vector<string> > readEncryptedReq(const char* f, string &path){
	map<string, vector<string> > m;
	string str;
	xml_document<> doc;
	ifstream file(f);
	stringstream buffer;
	buffer << file.rdbuf();
	file.close();
	string content(buffer.str());
	doc.parse<0>(&content[0]);
	xml_node<> *root = doc.first_node();
	path = root->first_attribute("path")->value();
	for (xml_node<> *node=root->first_node("Concept"); node; node=node->next_sibling()){
		string str1 = node->first_attribute("score")->value();
                string str2 = node->first_attribute("occurence")->value();
		string content = node->value();
		vector<string> vec;
		vec.push_back(str1);
		vec.push_back(str2);
		m[content] = vec;
		
	}
	
	return m;
}

map<string, string> readEncryptedUser(const char* f){
    map<string, string> m;
    int i = 0;
    xml_document<> doc;
    ifstream file(f);
    if (file){
       // cout << "ok" << endl;
	stringstream buffer;
	buffer << file.rdbuf();
	file.close();
	string content(buffer.str());
	doc.parse<0>(&content[0]);
	xml_node<> *root = doc.first_node();
	for (xml_node<> *node=root->first_node("Document"); node; node=node->next_sibling()){
		string str1 = node->first_attribute("score")->value();
		string content = node->value();
		m[content] = str1;
            //    cout << ++i << content << endl;
		
	}
     }
	
     return m;
}


long convertScore(double score){
	if (score >= 2)
		return 20;
	if (score >= 1)
		return 19;
	if (score >= 0.6)
		return 18;
	if (score >= 0.2)
		return 17;
	if (score >= 0.1)
		return 16;
	if (score >= 0.08)
		return 15;
	if (score >= 0.06)
		return 14;
	if (score >= 0.04)
		return 13;
	if (score >= 0.03)
		return 12;
	if (score >= 0.02)
		return 11;
	if (score >= 0.018)
		return 10;
	if (score >= 0.016)
		return 9;
	if (score >= 0.014)
		return 8;
	if (score >= 0.012)
		return 7;
	if (score >= 0.010)
		return 6;
	if (score >= 0.008)
		return 5;
	if (score >= 0.006)
		return 4;
	if (score >= 0.004)
		return 3;
	if (score >= 0.002)
		return 2;
	if (score > 0)
		return 1;
	return 0;
}

/*
	Get list files from a directory
*/

void listFiles( string path, vector<string> &vec )
{
   unsigned char isFile =0x8;
   string spath(path);
   DIR* dirFile = opendir( path.c_str() );
   if ( dirFile ) 
   {
      struct dirent* hFile;
      while (( hFile = readdir( dirFile )) != NULL ) 
      {
         if ( !strcmp( hFile->d_name, "."  )) continue;
         if ( !strcmp( hFile->d_name, ".." )) continue;

         // in linux hidden files all start with '.'
         if ( ( hFile->d_name[0] == '.' )) continue;

         // dirFile.name is the name of the file. Do whatever string comparison 
         // you want here. Something like:
	if (hFile->d_type == isFile)
		vec.push_back(spath+"/"+hFile->d_name);
	else
		listFiles(spath+"/"+hFile->d_name, vec);

      } 
      closedir( dirFile );
   }
}

void constructTableScores( int min, int max, int occ, int occZero){
   std::set<int> vect;
   int seuil = ((max - min) * occ + occZero ) * 2 ;
   ofstream file("Scores");
   file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << endl;
   file << "<Scores>" << endl;
   file << "<Score value = \"0\">" << endl;
   int i = 0;
   while (i<occZero){
         int val = rand() % seuil  ;
         if (vect.find(val) == vect.end()){
             vect.insert(val);
             printf("0 --> %d\n", val);
             file << "s" << val << endl;
             i++;
         }
   }
   file << "</Score>" << endl;
   for (int i = min; i<= max; i++){
      int j = 0;
      file << "<Score value = \"" << i << "\" >" << endl;
      while (j<occ){
         int val = rand() % seuil  ;
         if (vect.find(val) == vect.end()){
             vect.insert(val);
             printf("%d --> %d\n", i, val);
             j++;
             file << "s" << val << endl;
         }
      }
      file << "</Score>" << endl;
   }
   file << "</Scores>" << endl;
   file.close();
   cout << seuil << endl;
}

map<int, vector<string> > readScoresTable( const char* path){
        map<int, vector<string> > m;
	int str;
	xml_document<> doc;
	ifstream file(path);
	stringstream buffer;
	buffer << file.rdbuf();
	file.close();
	string content(buffer.str());
	doc.parse<0>(&content[0]);
	xml_node<> *root = doc.first_node();
	for (xml_node<> *node=root->first_node("Score"); node; node=node->next_sibling()){
		str = stoi(node->first_attribute("value")->value());
		string content = node->value();
                vector<string> vec = split(content, '\n');
                m[str] = vec;
	}
	
	return m;
}

vector<string> &split(const string &s, char delim, vector<string> &elems) {
    stringstream ss(s);
    string item;
    while (getline(ss, item, delim)) {
        elems.push_back(item);
    }
    return elems;
}

vector<string> split(const string &s, char delim){
   vector<string> elems;
   split(s, delim, elems);
   return elems;
}

void constructTableHE( map<int, vector<string> > m){
    
      map<int, vector<string> >::iterator im;

       for(im=m.begin(); im!=m.end(); im++){

           if ((*im).first == 0)
              for (int i=1; i<=1000; i++){
                    Ctxt c = encryption(0);
                    string path = "Table/";
                    path = path + (*im).second[i];
                    saveHE(path.c_str(), ctxtToString(c));
                 //   cout << (*im).second[i] << " Ok " << " ==> " << (*im).first << endl ;
              }
           else
              for (int i=1; i<=10; i++){
                    Ctxt c = encryption((*im).first);
                    string path = "Table/";
                    path = path + (*im).second[i];
                    saveHE(path.c_str(), ctxtToString(c));
                //    cout << (*im).second[i] << " Ok " << " ==> " << (*im).first << endl ;
              }
    
        }
}

void saveHE(const char* path, string value){
   ofstream file(path);
   file << value;
   file.close();
}

void encode(std::string& data) {
    std::string buffer;
    buffer.reserve(data.size());
    for(size_t pos = 0; pos != data.size(); ++pos) {
        switch(data[pos]) {
            case '&':  buffer.append("&amp;");       break;
            case '\"': buffer.append("&quot;");      break;
            case '\'': buffer.append("&apos;");      break;
            case '<':  buffer.append("&lt;");        break;
            case '>':  buffer.append("&gt;");        break;
            default:   buffer.append(&data[pos], 1); break;
        }
    }
    data.swap(buffer);
}

string getPathConcept(string title, string home){
   if (title.size() < 11)
      return NULL;
   else
      title = title.substr(11);

   title.erase(std::remove_if(title.begin(), title.end(),
    [](char c) { return !std::isalnum(c) && !std::isspace(c) ; } ),
    title.end());

   string rep1 = title.substr(0,1);
   string rep2 = title.substr(0,2);

   return home + "/" + rep1 + "/" + rep2 + "/" + title + ".he" ;
}

map<string, vector<string> > search(string &path_req){
   Ctxt s0 = encryption(0);
   map<string, map<string, vector<string> > > general_m;
   map<string, vector<string> > final_map;
   map<string, int> map_scores;
   string title;
   map<string, vector<string> > mm = readEncryptedReq(path_req.c_str(), path_req);
   map<string, vector<string> >::iterator im;
   map<string, string> map_user = readEncryptedUser("Users/user1");
   for(im=mm.begin(); im!=mm.end(); im++){
	string path = getPathConcept((*im).first, "Concepts");
     //   cout << path << endl;
        map<string, vector<string> > map_c = readEncryptedXml(path.c_str(), title);
        if (map_c.empty())
           continue;
        general_m[title] = map_c;
        map<string, vector<string> >::iterator im2;
        for(im2=map_c.begin(); im2!=map_c.end(); im2++){
           std::map<string, string>::iterator it_u = map_user.find((*im2).first);
           if ( it_u == map_user.end()){
             // cout << "NOT found " << (*im2).first << endl;;
              continue;
           }
           else
              cout << "found " << (*im2).first << endl;;
              
           std::map<string, int>::iterator it = map_scores.find((*im2).first);
           if ( it == map_scores.end()){
               map_scores[(*im2).first] = 1;
      //         cout << "not found ";
           }
           else{
               it->second = it->second + 1;
        //       cout << "found ";
            }
         //   cout << (*im2).first << " --> " << map_scores[(*im2).first] << endl;
        }
   }

  // cout << "imm here" << endl;
   
   int max;
   map<int, vector<string> > sorted_map = sort(map_scores, max);
   map<int, vector<string> >::reverse_iterator itt;
   int i;
   int nbr_doc =200;
   for(itt=sorted_map.rbegin(), i=0; itt!=sorted_map.rend() && i<nbr_doc ; itt++){
      for (vector<string>::iterator it = itt->second.begin(); it != itt->second.end(); it++){
      //    cout << i << " : " << *it << " -> " << itt->first << endl;
          vector<string> vec;
          vec.push_back(to_string(itt->first));
          Ctxt s1 = s0;
          Ctxt s2 = s0;
          map<string, map<string, vector<string> > >::iterator im3;
          for(im3=general_m.begin(); im3!=general_m.end(); im3++){
               map<string, vector<string> >::iterator it3 = im3->second.find(*it);
               if (it3 != im3->second.end()){
                   Ctxt ss = getEncryptedScore(im3->second[*it][0]) ;
                   ss.multiplyBy(getEncryptedScore(mm[im3->first][0]));
                   s1 += ss;
                   ss = getEncryptedScore(im3->second[*it][1]) ;
                   ss.multiplyBy(getEncryptedScore(mm[im3->first][1]));
                   s2 += ss;
                  // cout << decryption(getEncryptedScore(im3->second[*it][0])) << endl;
                  // cout << decryption(getEncryptedScore(mm[im3->first][0])) << endl;
               }
          }
          vec.push_back(ctxtToString(s1));
          vec.push_back(ctxtToString(s2));
          vec.push_back(ctxtToString(getEncryptedScore(map_user[*it])));
          cout << *it << " ----------------> " << map_user[*it] << endl;
          final_map[*it] = vec;          
          i++;
        //  cout << i << endl;
          if (i == nbr_doc)
              break;
      }
      if (i == nbr_doc)
              break;
   }
//   cout << max << endl;
   
   return final_map;
  
}

map<int, vector<string> > sort(map<string, int> map_scores, int &max){
   map<string, int >::iterator im;
   max = 0 ;
   map<int, vector<string> > sorted_map;
   for(im=map_scores.begin(); im!=map_scores.end(); im++){
           std::map<int, vector<string> >::iterator it = sorted_map.find((*im).second);
	   if ( it == sorted_map.end()){
               vector<string> v;
               v.push_back((*im).first);
               sorted_map[(*im).second] = v;
               if(max < (*im).second)
		  max = (*im).second ;
           }
           else{
               vector<string> v = it->second;
               v.push_back((*im).first);
               it->second = v;
            }
	
   }
   return sorted_map;
}

Ctxt getEncryptedScore(string score){
	ifstream file("Table/"+score);
	stringstream buffer;
	buffer << file.rdbuf();
	file.close();
	string content(buffer.str());
        return stringToCtxt(content);
}

map<string, vector<long> > decryptResult(map<string, vector<string> > m){
   map<string, vector<string> >::iterator it;
   map<string, vector<long> > res;
   for(it=m.begin(); it!=m.end(); it++){
	long s1 = stol(it->second[0]);
        long s2 = decryption(stringToCtxt(it->second[1]));
        long s3 = decryption(stringToCtxt(it->second[2]));  
        long s4 = decryption(stringToCtxt(it->second[3])); 
        vector<long> vec;
	vec.push_back(s1);
	vec.push_back(s2);
	vec.push_back(s3);
        vec.push_back(s4);
	res[it->first] = vec;
        cout << it->first << " : " << s1 << " | " << s2 << " | " << s3 << " | " << s4 << endl;
   }
   return res;

}

map<int, string> trier(map<string, vector<long> > m, string path_req, vector<int> &vec_res){
   map<string, vector<long> >::iterator it1;
   map<string, vector<long> >::iterator it2;
   map<int, string> res;
   for(it1 = m.begin(); it1 != m.end(); it1++){
      int k = 0;
      int max_return = 100;
      if (it1->second[2] == 0 || it1->second[3] == 0)
          continue;
      for(it2 = m.begin(); it2 != m.end(); it2++){
           /*if (it1->second[0] < it2->second[0])
              k++;
	   else*/ if (/*(it1->second[0] == it2->second[0]) &&*/ (it1->second[2] < it2->second[2]))
              k++;
           else if ( /*(it1->second[0] == it2->second[0]) &&*/ (it1->second[2] == it2->second[2]) && (it1->second[1] < it2->second[1]))
               k++;
           else if (/*(it1->second[0] == it2->second[0]) &&*/ (it1->second[2] == it2->second[2]) && (it1->second[1] == it2->second[1])) {
               size_t pos1 = it1->first.find_last_of("/") + 1;
               long x = stol(it1->first.substr(pos1, 5));
               pos1 = it2->first.find_last_of("/") + 1;
               long y = stol(it2->first.substr(pos1, 5)); 
             //  cout << x << " vs " << y << endl;
               if (x < y)
                 k++;
           }
          if (k==max_return)
             break;
      }
      if (k<max_return){
        res[k] = it1->first;
     //   cout << "comparing " << it1->first << " with " << path_req << endl;
         vector<int> v = comaprer(it1->first, path_req);
        cout << it1->first << endl ;
        cout << v[0] << " | " << v[1] << " | " << v[2] << " | " << v[3] << endl;
        vec_res = someVectors(vec_res, v);
      }
   }
  // cout << endl;
   return res;   
}
vector<int> comaprer(string path_req, string path_doc){
   int tab[] = {0, 0, 0, 0};
   vector<int> vec (tab, tab + 4);
   vector<string> vec1 = split(path_req, '/');
   vector<string> vec2 = split(path_doc, '/'); 
   if(vec1[9] == vec2[9])
      vec[0] = 1;
   if(vec1[10] == vec2[10])
      vec[1] = 1;
   if(vec1[11] == vec2[11])
      vec[2] = 1;
   if(vec1[12].substr(0,6) == vec2[12].substr(0,6)){
      vec[3] = 1;
      cout << path_req << endl;
      cout << path_doc << endl;
   }
   return vec;
}

vector<int> someVectors(vector<int> vec1, vector<int> vec2){
   int tab[] = {0, 0, 0, 0};
   vector<int> vec (tab, tab+4);
   for(int i=0; i<4; i++){
	vec[i] = vec1[i] + vec2[i];
    }
    return vec;
}

void updateXml(string path_doc, vector<string> list_docs, int percent, vector<string> list_zero){
        string title;
        map<string, vector<string> > mm = readEncryptedXml(path_doc.c_str(), title);
	int nbr_nodes= mm.size();
        percent = rand() % percent + 1 ;
        cout << path_doc << " - " << percent << endl; 
	int nbr_new = percent * nbr_nodes / 100 + 1 ;
        ofstream file(path_doc.c_str());
        file << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" << endl;
	file << "<Concept libelle=\"" << title << "\">" << endl;
	map<string, vector<string> >::iterator im;
	for(im=mm.begin(); im!=mm.end(); im++){
                file << "<Document score=\"" << (*im).second[0] << "\" occurence=\"" << (*im).second[1] <<"\">";
                string path = (*im).first; 
		encode(path);
                file << path;
		file << "</Document>" << endl;
	}
        for (int i=0; i<nbr_new; i++){
           int index = rand() % list_docs.size();
           string path = list_docs[index];
           int sc = rand() % 1000 + 1 ;
           string score = list_zero[sc];
           sc = rand() % 1000 + 1 ;
           string occ = list_zero[sc];
           encode(path);
           file << "<Document score=\"" << score << "\" occurence=\"" << occ <<"\">";
	   file << path ;
	   file << "</Document>" << endl;       
        }
	file << "</Concept>" << endl;
        file.close();

} 

vector<string> readListDocuments (string path){
    std::ifstream file(path.c_str());
    std::string str; 
    vector<string> v;
    while (std::getline(file, str))
    {
       v.push_back(str);   
    }
    return v;
}

inline bool ends_with(std::string const & value, std::string const & ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
}

