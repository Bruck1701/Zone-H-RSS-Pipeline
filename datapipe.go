package main


import "fmt"
import "github.com/ungerik/go-rss"
import "strings"
import "encoding/json"
import "net"
import "github.com/rainycape/geoip"


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
    Continent string `json:"continent"`
    Country string `json:"country"`
    Location Location `json:"location"`
}


type DeventPlus struct{
    Date string `json:"date"`
    Site string `json:"site"`
    Author string `json:"author"`
    IP string `json:"ip"`
    GeoIP GeoIP `json:"geoip"`

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
      d,_:=item.PubDate.Format("2006-01-02,15:04:05")
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

  ContinentName=""
  CountryName=""
  PointLocation:=Location{0,0}


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
  	    }

        if res.Continent.Name != nil{
          ContinentName=res.Continent.Name.String()

        }else{
          ContinentName=""
        }

        //fmt.Println(res)
        if res.Country.Name != nil{
          //CountryName=string(res.Country.Name)
          CountryName= res.Country.Name.String()
        }else{
          CountryName=""
        }
        PointLocation=Location{res.Longitude,res.Latitude}
      }
      Geopoint :=GeoIP{ContinentName,CountryName,PointLocation}
      nm := DeventPlus{m.Date,m.Site,m.Author,m.IP,Geopoint}
      jsonStr , _ := json.Marshal(nm)

      out <- jsonStr
    }
  close(out)
  }()
return out

}


func main(){

  var tmp DeventPlus

  out1:=getData()
  //fmt.Println(<-out1)
  out2:=ETL(out1)

  for elem := range out2 {
      //fmt.Println(elem)
      json.Unmarshal(elem,&tmp)
      fmt.Println(tmp)
      fmt.Println()
    }


}