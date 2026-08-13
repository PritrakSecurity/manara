package dspm

// InventoryScanner defines methods to scan file system assets
type InventoryScanner interface {
	// ScanFilePath scans a single file path and returns a populated Asset record (without persisting it)
	ScanFilePath(path string) (*Asset, error)
}
