package main

import (
	"net/http"
    "log"
    "fmt"
    "sync/atomic"
    "encoding/json"
    "strings"
    "github.com/joho/godotenv"
    "os"
    "database/sql"
    "github.com/kblasti/chirpy/internal/database"
    "github.com/kblasti/chirpy/internal/auth"
    "time"
    "github.com/google/uuid"
)

import _ "github.com/lib/pq"

type apiConfig struct {
	fileserverHits  atomic.Int32
    DB              *database.Queries
    platform        string
    secret          string
    polkaKey        string
}

type User struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
    IsChirpyRed bool    `json:"is_chirpy_red"`
}

type Chirp struct {
    ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
    Body      string    `json:"body"`
    UserID    uuid.UUID `json:"user_id"`
}

const expirationTime = time.Duration(3600) * time.Second

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        cfg.fileserverHits.Add(1)
        next.ServeHTTP(w, r)
    })
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter, r *http.Request) {
    hits := cfg.fileserverHits.Load()
    w.Header().Set("Content-Type", "text/html; charset=utf-8")
    w.WriteHeader(http.StatusOK)
    frmthits := fmt.Sprintf(`
    <html> 
        <body> 
            <h1>Welcome, Chirpy Admin</h1> 
            <p>Chirpy has been visited %d times!</p> 
        </body> 
    </html>`, hits)
    w.Write([]byte(frmthits))
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter, r *http.Request) {
    if cfg.platform != "dev" {
        respondWithError(w, 403, "Developer access required")
        return
    }
    cfg.fileserverHits.Store(0)
    cfg.DB.DeleteUsers(r.Context())
    w.Header().Set("Content-Type", "text/plain; charset=utf-8")
    w.WriteHeader(http.StatusOK)
    w.Write([]byte("Server Reset\n"))
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    payload := map[string]string{
        "error": msg,
    }
    data, err := json.Marshal(payload)
    if err != nil {
        http.Error(w, "Something went wrong", http.StatusInternalServerError)
        return
    }

    w.Write(data)
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(code)
    data, err := json.Marshal(payload)
    if err != nil {
        respondWithError(w, 500, "Something went wrong")
        return
    }

    w.Write(data)
}

func isBadWord(word string, badWords []string) bool {
    word = strings.ToLower(word)
    for _, bad := range badWords {
        if word == bad {
            return true
        }
    }
    return false
}

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter, r *http.Request) {
    type Input struct {
        Email string `json:"email"`
        Password string `json:"password"`
    }

    decoder := json.NewDecoder(r.Body)
    input := Input{}

    err := decoder.Decode(&input)
    if err != nil {
        respondWithError(w, 500, "Something went wrong")
        return
    }

    hashed, err := auth.HashPassword(input.Password)
    if err != nil {
        respondWithError(w, 500, "Something went wrong")
        return
    }

    dbUser, err := cfg.DB.CreateUser(r.Context(), database.CreateUserParams{
        Email:          input.Email,
        HashedPassword: hashed,
    })
    if err != nil {
        respondWithError(w, 500, "Something went wrong")
        return
    }

    appUser := User{
        ID:         dbUser.ID,
        CreatedAt:  dbUser.CreatedAt,
        UpdatedAt:  dbUser.UpdatedAt,
        Email:      dbUser.Email,
        IsChirpyRed: dbUser.IsChirpyRed,
    }

    respondWithJSON(w, 201, appUser)
    return
}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
    type Input struct {
        Email string `json:"email"`
        Password string `json:"password"`
    }

    type loginResponse struct {
        User
        Token string `json:"token"`
        RefreshToken string `json:"refresh_token"`
    }

    decoder := json.NewDecoder(r.Body)
    input := Input{}

    err := decoder.Decode(&input)
    if err != nil {
        respondWithError(w, 500, "Something went wrong")
        return
    }

    dbUser, err := cfg.DB.UserLogin(r.Context(), input.Email)
    if err != nil {
        if err == sql.ErrNoRows {
            respondWithError(w, 401, "Incorrect email or password")
            return
        } else {
            respondWithError(w, 500, "Something went wrong")
            return
        }
    }

    verified, err := auth.CheckPasswordHash(input.Password, dbUser.HashedPassword)
    if err != nil {
        respondWithError(w, 500, "Something went wrong")
        return
    }

    if verified == false {
        respondWithError(w, 401, "Incorrect email or password")
        return
    }

    token, err := auth.MakeJWT(dbUser.ID, cfg.secret, expirationTime)
    if err != nil {
        respondWithError(w, 500, "Error making token")
        return
    }

    refreshToken, err := auth.MakeRefreshToken()
    if err != nil {
        respondWithError(w, 500, "Error making refresh token")
        return
    }

    dbUserID := uuid.NullUUID{
        UUID:   dbUser.ID,
        Valid:  true,
    }

    _, err = cfg.DB.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
        Token: refreshToken,
        UserID: dbUserID,
    })
    if err != nil {
        respondWithError(w, 500, "Error saving refresh token")
        return
    }

    appUser := User{
        ID:         dbUser.ID,
        CreatedAt:  dbUser.CreatedAt,
        UpdatedAt:  dbUser.UpdatedAt,
        Email:      dbUser.Email,
        IsChirpyRed: dbUser.IsChirpyRed,
    }

    login := loginResponse{
        User:  appUser,
        Token: token,
        RefreshToken: refreshToken,
    }

    respondWithJSON(w, 200, login)
    return
}

func (cfg *apiConfig) handlerCreateChirp(w http.ResponseWriter, r *http.Request) {
    type parameters struct {
        Body   string    `json:"body"`
    }

    token, err := auth.GetBearerToken(r.Header)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, "Couldn't find JWT")
        return
    }

    userID, err := auth.ValidateJWT(token, cfg.secret)
    if err != nil {
        respondWithError(w, http.StatusUnauthorized, err.Error())
        return
    }

    decoder := json.NewDecoder(r.Body)
    params := parameters{}

    err = decoder.Decode(&params)
    if err != nil {
        respondWithError(w, 500, "Something went wrong")
        return
    }
    if len(params.Body) > 140 {
        respondWithError(w, 400, "Chirp is too long")
        return
    }

    splitString := strings.Split(params.Body, " ")
    badWords := []string{"kerfuffle", "sharbert", "fornax"}
    for i, word := range splitString {
        if isBadWord(word, badWords) {
            splitString[i] = "****"
        }
    }

    cleaned := strings.Join(splitString, " ")
    dbUserID := uuid.NullUUID{
        UUID:   userID,
        Valid:  true,
    }

    chirp, err := cfg.DB.CreateChirp(r.Context(), database.CreateChirpParams{
        Body:   cleaned,
        UserID: dbUserID,
    })
    if err != nil {
        respondWithError(w, 500, "Something went wrong")
        return
    }
    returnVal := Chirp{
        ID:         chirp.ID,
        CreatedAt:  chirp.CreatedAt,
        UpdatedAt:  chirp.UpdatedAt,
        Body:       chirp.Body,
        UserID:     chirp.UserID.UUID,
    }
    respondWithJSON(w, 201, returnVal)
    return
}

func (cfg *apiConfig) handlerGetChirps(w http.ResponseWriter, r *http.Request) {
    returnSlice := []Chirp{}
    chirps, err := cfg.DB.GetChirps(r.Context())
    if err != nil {
        respondWithError(w, 500, "Something went wrong")
        return
    }

    s := r.URL.Query().Get("author_id")



    if s != "" {
        userID, err := uuid.Parse(s)
        if err != nil {
            respondWithError(w, 500, err.Error())
            return
        }
        for _, chirp := range chirps {
            if userID == chirp.UserID.UUID {
                val := Chirp{
                    ID:         chirp.ID,
                    CreatedAt:  chirp.CreatedAt,
                    UpdatedAt:  chirp.UpdatedAt,
                    Body:       chirp.Body,
                    UserID:     chirp.UserID.UUID,
                }
                returnSlice = append(returnSlice, val)
            }
        }
    } else {
        for _, chirp := range chirps {
            val := Chirp{
                ID:         chirp.ID,
                CreatedAt:  chirp.CreatedAt,
                UpdatedAt:  chirp.UpdatedAt,
                Body:       chirp.Body,
                UserID:     chirp.UserID.UUID,
            }
            returnSlice = append(returnSlice, val)
        }
    }

    respondWithJSON(w, 200, returnSlice)
    return
}

func (cfg *apiConfig) handlerGetChirp(w http.ResponseWriter, r *http.Request) {
    idStr := r.PathValue("chirpID")

    chirpID, err := uuid.Parse(idStr)
    if err != nil {
        respondWithError(w, 400, "Client sent a bad path parameter")
        return
    }

    chirp, err := cfg.DB.GetChirp(r.Context(), chirpID)
    if err != nil {
        if err == sql.ErrNoRows {
            respondWithError(w, 404, "Chirp not found")
            return
        } else {
            respondWithError(w, 500, "Something went wrong")
            return
        }
    }

    val := Chirp{
            ID:         chirp.ID,
            CreatedAt:  chirp.CreatedAt,
            UpdatedAt:  chirp.UpdatedAt,
            Body:       chirp.Body,
            UserID:     chirp.UserID.UUID,
        }
    
    respondWithJSON(w, 200, val)
    return
}

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
    type tokenResponse struct {
        Token string `json:"token"`
    }
    
    token, err := auth.GetBearerToken(r.Header)
    if err != nil {
        respondWithError(w, 400, "Error with bearer token")
        return
    }

    user, err := cfg.DB.GetUserFromRefreshToken(r.Context(), token)
    if err != nil {
        respondWithError(w, 401, err.Error())
        return
    }

    jwtToken, err := auth.MakeJWT(user.ID, cfg.secret, expirationTime)
    if err != nil {
        respondWithError(w, 500, "Error making token")
        return
    }

    response := tokenResponse {
        Token: jwtToken,
    }

    respondWithJSON(w, 200, response)
    return
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
    token, err := auth.GetBearerToken(r.Header)
    if err != nil {
        respondWithError(w, 400, "Error with bearer token")
        return
    }

    err = cfg.DB.RevokeRefreshToken(r.Context(), token)
    if err != nil {
        respondWithError(w, 500, "Error revoking token")
        return
    }

    respondWithJSON(w, 204, nil)
    return
}

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
    type parameters struct {
        Email string `json:"email"`
        Password string `json:"password"`
    }

    token, err := auth.GetBearerToken(r.Header)
    if err != nil {
        respondWithError(w, 401, err.Error())
        return
    }

    userID, err := auth.ValidateJWT(token, cfg.secret)
    if err != nil {
        respondWithError(w, 401, err.Error())
        return
    }

    decoder := json.NewDecoder(r.Body)
    params := parameters{}

    err = decoder.Decode(&params)
    if err != nil {
        respondWithError(w, 500, err.Error())
        return
    }

    hashedPassword, err := auth.HashPassword(params.Password)
    if err != nil {
        respondWithError(w, 500, err.Error())
        return
    }

    dbUser, err := cfg.DB.UpdateUser(r.Context(), database.UpdateUserParams{
        Email: params.Email,
        HashedPassword: hashedPassword,
        ID: userID,
    })
    if err != nil {
        respondWithError(w, 500, err.Error())
        return
    }

    response := User{
        ID:         dbUser.ID,
        CreatedAt:  dbUser.CreatedAt,
        UpdatedAt:  dbUser.UpdatedAt,
        Email:      dbUser.Email,
        IsChirpyRed: dbUser.IsChirpyRed,
    }

    respondWithJSON(w, 200, response)
    return
}

func (cfg *apiConfig) handlerDeleteChirp(w http.ResponseWriter, r *http.Request) {
    token, err := auth.GetBearerToken(r.Header)
    if err != nil {
        respondWithError(w, 401, err.Error())
        return
    }

    userID, err := auth.ValidateJWT(token, cfg.secret)
    if err != nil {
        respondWithError(w, 403, err.Error())
        return
    }

    idStr := r.PathValue("chirpID")

    chirpID, err := uuid.Parse(idStr)
    if err != nil {
        respondWithError(w, 400, "Client sent a bad path parameter")
        return
    }

    chirp, err := cfg.DB.GetChirp(r.Context(), chirpID)
    if err != nil {
        if err == sql.ErrNoRows {
            respondWithError(w, 404, "Chirp not found")
            return
        } else {
            respondWithError(w, 500, "Something went wrong")
            return
        }
    }

    dbUserID := uuid.NullUUID{
        UUID:   userID,
        Valid:  true,
    }

    if chirp.UserID != dbUserID {
        respondWithError(w, 403, "Invalid authentication")
        return
    }

    err = cfg.DB.DeleteChirp(r.Context(), database.DeleteChirpParams{
        ID: chirp.ID,
        UserID: dbUserID,
    })
    if err != nil {
        respondWithError(w, 500, err.Error())
        return
    }

    respondWithJSON(w, 204, nil)
    return
}

func (cfg *apiConfig) handlerChirpyRed(w http.ResponseWriter, r *http.Request) {
    type parameters struct {
	    Event string `json:"event"`
	    Data  struct {
		    UserID string `json:"user_id"`
	    } `json:"data"`
    }

    apiKey, err := auth.GetAPIKey(r.Header)
    if err != nil {
        respondWithError(w, 401, err.Error())
        return
    }

    if apiKey != cfg.polkaKey {
        respondWithError(w, 401, err.Error())
        return
    }

    decoder := json.NewDecoder(r.Body)
    params := parameters{}

    err = decoder.Decode(&params)
    if err != nil {
        respondWithError(w, 500, err.Error())
        return
    }

    userID, err := uuid.Parse(params.Data.UserID)
    if err != nil {
        respondWithError(w, 404, err.Error())
        return
    }

    if params.Event == "user.upgraded" {
        err = cfg.DB.ChirpyRedAdd(r.Context(), userID)
        if err != nil {
            respondWithError(w, 404, err.Error())
            return
        } else {
            respondWithJSON(w, 204, nil)
            return
        }
    }

    respondWithJSON(w, 204, nil)
    return
}

func main() {
    godotenv.Load()
    dbURL := os.Getenv("DB_URL")
    db, err := sql.Open("postgres", dbURL)
    if err != nil {
        log.Fatal(err)
    }
    port := "8080"
    filepathRoot := "/app/"
    dbQueries := database.New(db)
    cfg := &apiConfig{
	    fileserverHits: atomic.Int32{},
	    DB:             dbQueries,
        platform:       os.Getenv("PLATFORM"),
        secret:         os.Getenv("SECRET"),
        polkaKey:       os.Getenv("POLKA_KEY"),
    }
    mux := http.NewServeMux()
    mux.Handle(filepathRoot, cfg.middlewareMetricsInc(http.StripPrefix("/app", http.FileServer(http.Dir(".")))))
    mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/plain; charset=utf-8")
        w.WriteHeader(http.StatusOK)
        w.Write([]byte("OK\n"))
    })
    mux.HandleFunc("GET /admin/metrics", cfg.handlerMetrics)
    mux.HandleFunc("POST /admin/reset", cfg.handlerReset)
    mux.HandleFunc("POST /api/users", cfg.handlerCreateUser)
    mux.HandleFunc("POST /api/chirps", cfg.handlerCreateChirp)
    mux.HandleFunc("GET /api/chirps", cfg.handlerGetChirps)
    mux.HandleFunc("GET /api/chirps/{chirpID}", cfg.handlerGetChirp)
    mux.HandleFunc("POST /api/login", cfg.handlerLogin)
    mux.HandleFunc("POST /api/refresh", cfg.handlerRefresh)
    mux.HandleFunc("POST /api/revoke", cfg.handlerRevoke)
    mux.HandleFunc("PUT /api/users", cfg.handlerUpdateUser)
    mux.HandleFunc("DELETE /api/chirps/{chirpID}", cfg.handlerDeleteChirp)
    mux.HandleFunc("POST /api/polka/webhooks", cfg.handlerChirpyRed)

    srv := &http.Server{
        Addr:    ":" + port,
        Handler: mux,
    }  

    log.Printf("Serving files from %s on port: %s\n", filepathRoot, port)
    log.Fatal(srv.ListenAndServe())
}