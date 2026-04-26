package python

import "os"

func writeFileRaw(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
