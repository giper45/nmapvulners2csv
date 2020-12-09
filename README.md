# nmapvulners2cvs
Convert Nmap vulners script output to csv

## Getting Started  
Run nmap with enabled script vulners and save xml output, for example:   
```  
nmap -sV --script vulners -oX <nmap_output.xml>  
```  

### Prerequisites   
Install dependencies by using the following command: 
``` 
pip install -r requirements.txt
```

### Run   
To run the converter:   
```  
python nmap <nmap_output.xml>   
``` 

the script will generate a file output.csv in output dir   

### Evidences Description  
nmap vulners script does not generate descriptions for vulnerabilities. You can add `--descr` flag to add descriptions in csv.  The script scrapes description information from vulners site. The command is more time-expensive and send several HTTP requests against vulners website. Not tested for IP ban and network issues.     

## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License
Distributed under Apache 2 License. See `LICENSE` for more information. 



