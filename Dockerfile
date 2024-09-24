# Copyright 2024 go-dataspace
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#     https://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM docker.io/library/golang:1.22 as builder
WORKDIR /app
COPY . ./
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -ldflags="-extldflags=-static"  -a -o ./reference-provider ./cmd/main.go

# Copy a few pdfs from the internet archive for testing purposes
RUN mkdir -p /var/lib/run-dsp/fsprovider/User1
RUN mkdir -p /var/lib/run-dsp/fsprovider/User2
RUN curl https://ia802802.us.archive.org/24/items/GuestAndChrimes1848/Guest%20and%20Chrimes%201848.pdf -o /var/lib/run-dsp/fsprovider/User1/ex1.pdf
RUN curl https://ia600808.us.archive.org/4/items/ParkerAndWhiteAgriculturalCatalogue/Parker%20and%20White%20Agricultural%20Catalogue.pdf -o /var/lib/run-dsp/fsprovider/User1/ex2.pdf
RUN curl https://ia802809.us.archive.org/6/items/EdwardMClarkeListOfPrices1837/Edward%20M%20Clarke%20List%20of%20Prices%201837.pdf -o /var/lib/run-dsp/fsprovider/User2/ex1.pdf
RUN curl https://ia600808.us.archive.org/25/items/AManualOfScandanavianMythologyGPigott/A%20Manual%20of%20Scandanavian%20Mythology%20-%20G%20Pigott.pdf -o /var/lib/run-dsp/fsprovider/User2/ex2.pdf

FROM scratch
WORKDIR /app
COPY --from=builder /app/reference-provider ./
COPY --from=builder /var/lib/run-dsp /var/lib/
COPY --from=alpine:latest /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

ENTRYPOINT [ "./reference-provider" ]
