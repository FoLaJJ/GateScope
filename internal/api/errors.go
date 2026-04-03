package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type APIError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

func (e *APIError) Error() string {
	return e.Message
}

func respondError(c *gin.Context, code int, message string, detail ...string) {
	e := APIError{Code: code, Message: message}
	if len(detail) > 0 {
		e.Detail = detail[0]
	}
	c.JSON(code, gin.H{"error": e})
}

func respondOK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, data)
}

func respondCreated(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, data)
}

func respondMessage(c *gin.Context, msg string) {
	c.JSON(http.StatusOK, gin.H{"message": msg})
}

type PaginatedResponse struct {
	Data  any   `json:"data"`
	Total int64 `json:"total"`
	Page  int   `json:"page"`
	Limit int   `json:"limit"`
	Pages int   `json:"pages"`
}

func respondPaginated(c *gin.Context, data any, total int64, page, limit int) {
	pages := 0
	if limit > 0 {
		pages = int(total) / limit
		if int(total)%limit > 0 {
			pages++
		}
	}
	c.JSON(http.StatusOK, PaginatedResponse{
		Data:  data,
		Total: total,
		Page:  page,
		Limit: limit,
		Pages: pages,
	})
}

func getPagination(c *gin.Context) (page, limit, offset int) {
	limit = getIntQuery(c, "limit", 20)
	if limit > 500 {
		limit = 500
	}
	if limit < 1 {
		limit = 20
	}
	page = getIntQuery(c, "page", 1)
	if page < 1 {
		page = 1
	}
	offset = (page - 1) * limit
	return
}
