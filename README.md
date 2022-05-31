# moto
high-speed motorcycle，可以上高速的摩托车～    


#### build for linux    

CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo   

#### build for macos

CGO_ENABLED=0 GOOS=darwin go build -a -installsuffix cgo

#### build for windows 

CGO_ENABLED=0 GOOS=windows go build -a -installsuffix cgo
