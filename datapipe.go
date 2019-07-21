package main


import "fmt"
import "github.com/ungerik/go-rss"
import "strings"
import "encoding/json"
import "net"
import "github.com/rainycape/geoip"
import "github.com/olivere/elastic"
import "log"
import "os"
import "context"
import ("net/http"; "crypto/tls")
import "hash/fnv"
import "strconv"
import "bufio"



type Devent struct{
    Date string `json:"date"`
    Site string `json:"site"`
    Author string `json:"author"`
    IP string `json:"ip"`
}

type Location struct{
  Lon float64 `json:"lon"`
  Lat float64 `json:"lat"`
}


type GeoIP struct{

    Location Location `json:"location"`
}


type DeventPlus struct{
    Date string `json:"date"`
    Site string `json:"site"`
    Author string `json:"author"`
    IP string `json:"ip"`
    Continent string `json:"continent"`
    Country string `json:"country"`
    GeoIP GeoIP `json:"geoip"`

}



const (
	indexName    = "logstash"
	docType      = "_doc"
	appName      = "zoneh"
	indexMapping = `{
    "settings":{
            "number_of_shards":1,
            "number_of_replicas":0
          },
          "mappings" : {
							"_doc" : {
								"properties" : {
                  "date" : { "type" : "date" },
									"site" : { "type" : "text" , "fields": {  "raw": {  "type":  "keyword" } } },
									"author" : { "type" : "text", "fields": {  "raw": {  "type":  "keyword" } }},
                  "ip" : { "type" : "ip"},
                  "continent" : { "type" : "text", "fields": {  "raw": {  "type":  "keyword" } }},
                  "country" : { "type" : "text", "fields": {  "raw": {  "type":  "keyword" } }},
                  "location":{"type":"geo_point"}
								}
							}
						}
					}`
)



func hash(s string) uint64 {
        h := fnv.New64a()
        h.Write([]byte(s))
        return h.Sum64()
}



func getData() <- chan []byte{

  var ip_str string
   out := make(chan []byte)

  channel, err := rss.Read("http://www.zone-h.org/rss/specialdefacements")
  if err != nil {
    fmt.Println(err)
  }

  fmt.Println(channel.Title)
  go func() {

    for _, item := range channel.Item {
      d,_:=item.PubDate.Format("2006-01-02 15:04:05")
      dst:=strings.Split(item.Description," notified by ")
      s,a:=dst[0],dst[1]
      //fmt.Println(s)
      server:=strings.Replace(s,"http://","",-1)

      if strings.Contains(server,"/"){
        server=strings.Split(server,"/")[0]
      }
      ip, err := net.LookupIP(server)

      if err != nil {
        ip_str="0.0.0.0"
      }else{
        ip_str=ip[0].String()
      }
      d=strings.Replace(d," ","T",-1)
      fmt.Println(d)
      ev1 :=Devent{d,s,a,ip_str}
      jsonStr , err := json.Marshal(ev1)
      out <- jsonStr
      if err!= nil{
        fmt.Println(err)
        return
      }
    }
  close(out)
  }()
  return out

}





func ETL(in <- chan []byte) <-chan []byte{
  var m Devent
  //var nm DeventP
  var ContinentName,CountryName string
  //var Geopoint GeoIP

  ContinentName="N/A"
  CountryName="N/A"
  PointLocation:=Location{181,91}


  out := make(chan []byte)
  db, err := geoip.Open("data/GeoLite2-City_20190514/GeoLite2-City.mmdb")
  if err!=nil{
    panic(err)
  }

  go func(){
    for n :=range in{
      //fmt.Println("Unmarshalling from channel!")
      json.Unmarshal(n,&m)


      if m.IP!="0.0.0.0"{

        res, err := db.Lookup(m.IP)

  	    if err != nil {
          fmt.Println("LOCATION OF IP NOT FOUND")
          ContinentName="N/A"
          CountryName="N/A "
          PointLocation=Location{181,91}

  	    }else{

          if res.Continent.Name != nil{
            ContinentName=res.Continent.Name.String()
          }else{
            ContinentName="N/A"
          }
          //fmt.Println(res)
          if res.Country.Name != nil{
            //CountryName=string(res.Country.Name)
            CountryName= res.Country.Name.String()
          }else{
            CountryName="N/A"
          }
          PointLocation=Location{res.Longitude,res.Latitude}
        }
        filename:= strconv.FormatUint(hash(m.Date+m.Site+m.Author),10)
        f, err := os.Create("tmp/"+filename)
        w := bufio.NewWriter(f)
        command := fmt.Sprintf("start %s -m sfp_dns,sfp_fraudguard,sfp_malwarepatrol,sfp_censys,sfp_ipinfo,sfp_shodan,sfp_dronebl,sfp_honeypot,sfp_alienvault,sfp_duckduckgo,sfp_whois,sfp_virustotal,sfp_intelx,sfp_watchguard,sfp_abuseipdb,sfp_ripe,sfp_email -n %s -w\n",m.IP,m.Site)
        n4, err := w.WriteString(command)

        if err != nil{
          fmt.Println("File error:",err)
        }
        fmt.Println("Wrote: ",n4, "bytes")
        w.Flush()


      }


      Geopoint :=GeoIP{PointLocation}
      nm := DeventPlus{m.Date,m.Site,m.Author,m.IP,ContinentName,CountryName,Geopoint}
      jsonStr , _ := json.Marshal(nm)
      PointLocation=Location{181,91}
      ContinentName="N/A"
      CountryName="N/A"

      out <- jsonStr
    }
  close(out)
  }()
return out

}


func output(in <- chan []byte){

  var tmp DeventPlus


  tr := &http.Transport{
  TLSClientConfig: &tls.Config{InsecureSkipVerify : true},
  }
  noCheckClient := &http.Client{Transport: tr}

  //ctx:=context.Background()

  client, err := elastic.NewClient(
      elastic.SetHttpClient(noCheckClient),
      elastic.SetURL("https://localhost:9200"),
      elastic.SetBasicAuth("admin","admin"),
      elastic.SetHealthcheck(false),
      elastic.SetScheme("https"),
      elastic.SetSniff(false),
      elastic.SetErrorLog(log.New(os.Stderr, "", log.LstdFlags)),
		  elastic.SetInfoLog(log.New(os.Stdout, "", log.LstdFlags)),
      )


  if err != nil  {
    fmt.Println("entrei aqui")

    panic(err)
  }
  log.Printf("client.running? %v",client.IsRunning())

  fmt.Println(client)
  //fmt.Println(ctx)

// Zone-H
  exists, err := client.IndexExists(indexName).Do(context.Background())

  if err != nil {
  	// Handle error
    fmt.Println("ERRO EXISTs>",err)

  }
  fmt.Println(exists)

  if !exists {
  	fmt.Println("Index does not exist yet")
    //ctx=context.Background()
    res, err := client.CreateIndex(indexName).Body(indexMapping).Do(context.Background())

    if err != nil {

      fmt.Println(err)
      //return err
    }

    if !res.Acknowledged {
      fmt.Println("Error message from creating index: -> ",res)
      //return errors.New("CreateIndex was not acknowledged. Check that timeout value is correct.")
    }

  }
  //bulkRequest := client.Bulk()



    for elem:= range in {
      json.Unmarshal(elem,&tmp)
      id:= hash(tmp.Date+tmp.Site+tmp.Author)

      result,err :=client.Index().Index(indexName).Type(docType).Id(strconv.FormatUint(id,10)).BodyJson(tmp).Do(context.Background())
      fmt.Println(result)
      fmt.Println(err)

      fmt.Println("id: ",id)
      fmt.Println(tmp)
      fmt.Println()
    }

    _, err = client.Flush().Index(indexName).Do(context.Background())
  	if err != nil {
  		panic(err)
  	}


}





func main(){


  out1:=getData()
  out2:=ETL(out1)
  output(out2)


}
