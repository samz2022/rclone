// Package api provides types for the Drime API
package api

import (
	"fmt"
)

// FileEntry represents a file or folder in Drime
type FileEntry struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	FileName    string `json:"file_name"`
	Type        string `json:"type"` // "folder", "image", "text", "audio", "video", "pdf"
	FileSize    int64  `json:"file_size"`
	FileHash    string `json:"file_hash"`
	Path        string `json:"path"`
	UpdatedAt   string `json:"updated_at"`
	CreatedAt   string `json:"created_at"`
	ParentID    *int   `json:"parent_id"`
	UserID      *int   `json:"user_id"`
	Mime        string `json:"mime"`
	Extension   string `json:"extension"`
	Public      bool   `json:"public"`
	IsDeleted   int    `json:"is_deleted"`
	DeletedAt   string `json:"deleted_at"`
	Description string `json:"description"`
	Color       string `json:"color"`
	Backup      bool   `json:"backup"`
	Tracked     int    `json:"tracked"`
	DiskPrefix  string `json:"disk_prefix"`
	Thumbnail   bool   `json:"thumbnail"`
	MuxStatus   string `json:"mux_status"`
	ThumbnailURL string `json:"thumbnail_url"`
}

// Error represents an error response from the API
type Error struct {
	Message string `json:"message"`
	Status  string `json:"status"`
	Code    int    `json:"code"`
}

// Error implements the error interface
func (e *Error) Error() string {
	if e.Code != 0 {
		return fmt.Sprintf("drime error %d: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("drime error: %s", e.Message)
}

// UploadResponse represents the response from uploading a file
type UploadResponse struct {
	Status    string     `json:"status"`
	FileEntry *FileEntry `json:"fileEntry"`
}

// ListResponse represents the paginated response from listing files
type ListResponse struct {
	CurrentPage int          `json:"current_page"`
	Data        []*FileEntry `json:"data"`
	FirstPageURL string      `json:"first_page_url"`
	From        int          `json:"from"`
	LastPage    int          `json:"last_page"`
	LastPageURL string       `json:"last_page_url"`
	NextPageURL string       `json:"next_page_url"`
	Path        string       `json:"path"`
	PerPage     int          `json:"per_page"`
	PrevPageURL string       `json:"prev_page_url"`
	To          int          `json:"to"`
	Total       int          `json:"total"`
}
