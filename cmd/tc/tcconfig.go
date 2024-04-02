package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v2"
)

// BPFMapConfig 用于表示BPF Map中的配置项
type BPFMapConfig struct {
	Key   int32
	Value int32
}

// Config 结构用于解析配置文件
type Config struct {
	Device   string            `yaml:"device"`
	Protocol map[string][]int `yaml:"protocol"`
}

// Read configuration file
func readConfig(filename string) (*Config, error) {
	// 获取文件的绝对路径
	fullPath, err := filepath.Abs(filename)
	if err != nil {
		return nil, err
	}
	fmt.Printf("Reading configuration file: %s\n", fullPath)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data := bytes.NewBuffer(nil)
	_, err = io.Copy(data, file)
	if err != nil {
		return nil, err
	}

	config := &Config{}
	err = yaml.Unmarshal(data.Bytes(), config)
	if err != nil {
		return nil, err
	}

	return config, nil
}