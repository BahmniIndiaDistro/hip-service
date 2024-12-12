FROM --platform=$BUILDPLATFORM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env
ARG TARGETARCH
WORKDIR /app

# Copy csproj and restore as distinct layers
COPY HipServiceSrc.sln ./
COPY src/In.ProjectEKA.DefaultHip/*.csproj ./src/In.ProjectEKA.DefaultHip/
COPY src/In.ProjectEKA.HipLibrary/*.csproj ./src/In.ProjectEKA.HipLibrary/
COPY src/In.ProjectEKA.HipService/*.csproj ./src/In.ProjectEKA.HipService/
RUN dotnet restore -a $TARGETARCH

# Copy everything else and build
COPY . .
WORKDIR /app/src/In.ProjectEKA.DefaultHip
RUN dotnet build -c Release -o /app -a $TARGETARCH

WORKDIR /app/src/In.ProjectEKA.HipService
RUN dotnet publish -c Release -o /app -a $TARGETARCH

# Build runtime image
FROM mcr.microsoft.com/dotnet/aspnet:8.0-alpine

RUN mkdir app

WORKDIR /app

COPY --from=build-env /app .

ENTRYPOINT ["dotnet", "In.ProjectEKA.HipService.dll"]
EXPOSE 80