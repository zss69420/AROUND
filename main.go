package main

import (
	"fmt"
	"net/http"
	"encoding/json"
	"log"
	"strconv"
	elastic "gopkg.in/olivere/elastic.v3"
	"reflect"
	"github.com/pborman/uuid"
	"context"
        "cloud.google.com/go/storage"
	"io"
	"github.com/auth0/go-jwt-middleware"
        "github.com/dgrijalva/jwt-go"
        "github.com/gorilla/mux"
	"path/filepath"

)

const(
      INDEX = "around"
      TYPE = "post"
      DISTANCE = "200km"
      // Needs to update
      //PROJECT_ID = "around-xxx"
      //BT_INSTANCE = "around-post"
      // Needs to update this URL if you deploy it to cloud.
      ES_URL = "http://34.94.183.183:9200"
      BUCKET_NAME = "post-images-258607"
      API_PREFIX = "/api/v1"
)

var (
	mediaTypes = map[string]string{
	".jpeg": "image",
	".jpg": "image",
	".gif": "image",
	".png": "image",
	".mov": "video",
	".mp4": "video",
	".avi": "video",
	".flv": "video",
	".wmv": "video",
	}
)

//JWT secret
var mySigningKey = []byte("secret")

type Location struct {
	Lat float64 `json:"lat"`
	Lon float64 `json:"lon"`
}

type Post struct {
	User string `json:"user"`
	Message string `json:"message"`
	Location Location `json:"location"`
	Url    string `json:"url"`
	Type string `json:"type"`
	Face float64 `json:"face"`
}

func main() {
	// Create a client
	client, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
	if err != nil {
		panic(err)
		return
	}

	// Use the IndexExists service to check if a specified index exists.
	exists, err := client.IndexExists(INDEX).Do()
	if err != nil {
		panic(err)
	}
	if !exists {
		// Create a new index.
		mapping := `{
			"mappings":{
				"post":{
					"properties":{
						"location":{
							"type":"geo_point"
						}
					}
				}
			}
		}`
		_, err := client.CreateIndex(INDEX).Body(mapping).Do()
		if err != nil {			// Handle error
			panic(err)
		}
	}

	fmt.Println("started-service")

      // Here we are instantiating the gorilla/mux router
      //Create a new router on top of the existing http router as we need to check auth.
      r := mux.NewRouter()

      //Create a new JWT middleware with a Option that uses the key ‘mySigningKey’ such that we know this token is from our s      erver. The signing method is the default HS256 algorithm such that data is encrypted.
      var jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
             ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
                    return mySigningKey, nil
             },
             SigningMethod: jwt.SigningMethodHS256,
      })

      //It means we use jwt middleware to manage these endpoints and if they don’t have valid token, we will reject them
      r.Handle(API_PREFIX+"/post", jwtMiddleware.Handler(http.HandlerFunc(handlerPost))).Methods("POST")
      r.Handle(API_PREFIX+"/search", jwtMiddleware.Handler(http.HandlerFunc(handlerSearch))).Methods("GET")
      r.Handle(API_PREFIX+"/cluster", jwtMiddleware.Handler(http.HandlerFunc(handlerCluster)))
      r.Handle(API_PREFIX+"/login", http.HandlerFunc(loginHandler)).Methods("POST")
      r.Handle(API_PREFIX+"/signup", http.HandlerFunc(signupHandler)).Methods("POST")

      // Backend endpoints.
      http.Handle(API_PREFIX+"/", r)
      // Frontend endpoints.
      http.Handle("/", http.FileServer(http.Dir("build")))
      log.Fatal(http.ListenAndServe(":8080", nil))


}

func handlerPost (w http.ResponseWriter, r *http.Request) {
     w.Header().Set("Content-Type", "application/json")
     w.Header().Set("Access-Control-Allow-Origin", "*")
     w.Header().Set("Access-Control-Allow-Headers", "Content-Type,Authorization")

      user := r.Context().Value("user")
      claims := user.(*jwt.Token).Claims
      username := claims.(jwt.MapClaims)["username"]

      // 32 << 20 is the maxMemory param for ParseMultipartForm, equals to 32MB (1MB = 1024 * 1024 bytes = 2^20 bytes)
      // After you call ParseMultipartForm, the file will be saved in the server memory with maxMemory size.
      // If the file size is larger than maxMemory, the rest of the data will be saved in a system temporary file.
      r.ParseMultipartForm(32 << 20)

      // Parse from form data.
      fmt.Printf("Received one post request %s\n", r.FormValue("message"))
      lat, _ := strconv.ParseFloat(r.FormValue("lat"), 64)
      lon, _ := strconv.ParseFloat(r.FormValue("lon"), 64)
      p := &Post{
	     User:    username.(string),
             Message: r.FormValue("message"),
             Location: Location{
                    Lat: lat,
                    Lon: lon,
             },
      }

      id := uuid.New()

      file, _, err := r.FormFile("image")
      if err != nil {
             http.Error(w, "Image is not available", http.StatusInternalServerError)
             fmt.Printf("Image is not available %v.\n", err)
             return
      }
      defer file.Close()

     ctx := context.Background()

     // replace it with your real bucket name.
      _, attrs, err := saveToGCS(ctx, file, BUCKET_NAME, id)
      if err != nil {
             http.Error(w, "GCS is not setup", http.StatusInternalServerError)
             fmt.Printf("GCS is not setup %v\n", err)
	             return
      }

      im, header, _ := r.FormFile("image")
	defer im.Close()
	suffix := filepath.Ext(header.Filename)
	// Client needs to know the media type so as to render it.
	if t,ok := mediaTypes[suffix]; ok {
		p.Type = t
	} else {
		p.Type = "unknown"
	}
	// ML Engine only supports jpeg.
	if suffix == ".jpeg" {
		if score, err := annotate(im); err != nil {
			http.Error(w, "Failed to annotate the image", http.StatusInternalServerError)
			fmt.Printf("Failed to annotate the image %v\n", err)
			return
		} else {
			p.Face = score
		}
	}

      // Update the media link after saving to GCS.
      p.Url = attrs.MediaLink

      // Save to ES.
      saveToES(p, id)

      // Save to BigTable.
      //saveToBigTable(p, id)

}

func handlerCluster(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received one request for clustering")
	w.Header().Set("AccessControlAllowOrigin", "*")
	w.Header().Set("ContentType", "application/json")
	w.Header().Set("AccessControlAllowHeaders","ContentType, Authorization")
	if r.Method != "GET" {
		return
	}
	term := r.URL.Query().Get("term")
	// Create a client
	client, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
	if err != nil {
		http.Error(w, "ES is not setup", http.StatusInternalServerError)
		fmt.Printf("ES is not setup %v\n", err)
		return
	}
	// Range query.
	// For details, https://www.elastic.co/guide/en/elasticsearch/reference/current/querydslrangequery.html
	q := elastic.NewRangeQuery(term).Gte(0.9)
	searchResult, err := client.Search().
	Index(INDEX).
	Query(q).
	Pretty(true).
	Do()
	if err != nil {
		// Handle error
		m := fmt.Sprintf("Failed to query ES %v", err)
		fmt.Println(m)
		http.Error(w, m, http.StatusInternalServerError)
	}
	// searchResult is of type SearchResult and returns hits, suggestions,
	// and all kinds of other information from Elasticsearch.
	fmt.Printf("Query took %d milliseconds\n", searchResult.TookInMillis)
	// TotalHits is another convenience function that works even when something goes wrong.
	fmt.Printf("Found a total of %d post\n", searchResult.TotalHits())
	// Each is a convenience function that iterates over hits in a search result.
	// It makes sure you don't need to check for nil values in the response.
	// However, it ignores errors in serialization.
	var typ Post
	var ps []Post
	for _, item := range searchResult.Each(reflect.TypeOf(typ)) {
		p := item.(Post)
		ps = append(ps, p)
	}
	js, err := json.Marshal(ps)
	if err != nil {
		m := fmt.Sprintf("Failed to parse post object %v", err)
		fmt.Println(m)
		http.Error(w, m, http.StatusInternalServerError)
		return
	}
	w.Write(js)
}


func saveToGCS(ctx context.Context, r io.Reader, bucketName, name string) (*storage.ObjectHandle, *storage.ObjectAttrs, error) {
     client, err := storage.NewClient(ctx)
      if err != nil {
             return nil, nil, err
      }
      defer client.Close()

      bucket := client.Bucket(bucketName)
      // Next check if the bucket exists
      if _, err = bucket.Attrs(ctx); err != nil {
             return nil, nil, err
      }

      obj := bucket.Object(name)
      w := obj.NewWriter(ctx)
      if _, err := io.Copy(w, r); err != nil {
             return nil, nil, err
      }
      if err := w.Close(); err != nil {
             return nil, nil, err
      }
      if err := obj.ACL().Set(ctx, storage.AllUsers, storage.RoleReader); err != nil {
             return nil, nil, err
      }

      attrs, err := obj.Attrs(ctx)
      fmt.Printf("Post is saved to GCS: %s\n", attrs.MediaLink)
      return obj, attrs, err


}


// Save a post to ElasticSearch
func saveToES(p *Post, id string) {
	// Create a client
	es_client, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
	if err != nil {
		panic(err)
		return
	}
	// Save it to index
	_, err = es_client.Index().
		Index(INDEX).
		Type(TYPE).
		Id(id).
		BodyJson(p).
		Refresh(true).
		Do()
		if err != nil {
		panic(err)
		return
	}

	fmt.Printf("Post is saved to Index: %s\n", p.Message)
}


func handlerSearch(w http.ResponseWriter, r *http.Request) {
      fmt.Println("Received one request for search")
      lat, _ := strconv.ParseFloat(r.URL.Query().Get("lat"), 64)
      lon, _ := strconv.ParseFloat(r.URL.Query().Get("lon"), 64)
      // range is optional
      ran := DISTANCE
      if val := r.URL.Query().Get("range"); val != "" {
         ran = val + "km"
      }

      fmt.Printf( "Search received: %f %f %s\n", lat, lon, ran)

      // Create a client
      client, err := elastic.NewClient(elastic.SetURL(ES_URL), elastic.SetSniff(false))
      if err != nil {
             panic(err)
             return


      }
	// Define geo distance query as specified in
      // https://www.elastic.co/guide/en/elasticsearch/reference/5.2/query-dsl-geo-distance-query.html
      q := elastic.NewGeoDistanceQuery("location")
      q = q.Distance(ran).Lat(lat).Lon(lon)

      // Some delay may range from seconds to minutes. So if you don't get enough results. Try it later.
      searchResult, err := client.Search().
             Index(INDEX).
             Query(q).
             Pretty(true).
             Do()
      if err != nil {
             // Handle error
             panic(err)
      }

      // searchResult is of type SearchResult and returns hits, suggestions,
      // and all kinds of other information from Elasticsearch.
      fmt.Printf("Query took %d milliseconds\n", searchResult.TookInMillis)
      // TotalHits is another convenience function that works even when something goes wrong.
      fmt.Printf("Found a total of %d post\n", searchResult.TotalHits())

      // Each is a convenience function that iterates over hits in a search result.
      // It makes sure you don't need to check for nil values in the response.
      // However, it ignores errors in serialization.
      var typ Post
      var ps []Post
      for _, item := range searchResult.Each(reflect.TypeOf(typ)) { // instance of
             p := item.(Post) // p = (Post) item
             fmt.Printf("Post by %s: %s at lat %v and lon %v\n", p.User, p.Message, p.Location.Lat, p.Location.Lon)
             // TODO(student homework): Perform filtering based on keywords such as web spam etc.
             ps = append(ps, p)

      }
      js, err := json.Marshal(ps)
      if err != nil {
             panic(err)
             return
      }

      w.Header().Set("Content-Type", "application/json")
      w.Header().Set("Access-Control-Allow-Origin", "*")
      w.Write(js)

 }
