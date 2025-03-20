/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 */

 package conf

 import (
	 "errors"
	 "os"
	 "path/filepath"
	 "strings"
 
	 "golang.zx2c4.com/wireguard/windows/conf/dpapi"
 )
 
 const (
	 configFileSuffix            = ".conf.dpapi"
	 configFileUnencryptedSuffix = ".conf"
 )
 
 func ListConfigNames() ([]string, error) {
	 configFileDir, err := tunnelConfigurationsDirectory()
	 if err != nil {
		 return nil, err
	 }
	 files, err := os.ReadDir(configFileDir)
	 if err != nil {
		 return nil, err
	 }
 
	 configs := make([]string, 0, len(files))
	 for _, file := range files {
		 // Überspringe Einträge, die keine reguläre Datei sind.
		 if !file.Type().IsRegular() {
			 continue
		 }
 
		 // Schnelle Prüfung des Dateinamens.
		 name := file.Name()
		 if !(strings.HasSuffix(name, configFileSuffix) || strings.HasSuffix(name, configFileUnencryptedSuffix)) {
			 continue
		 }
 
		 // Lese Dateiinformationen erst, wenn der Name passt.
		 info, err := file.Info()
		 if err != nil {
			 continue // Alternativ: Fehler loggen
		 }
 
		 // Prüfe, ob die Datei Lesezugriff erlaubt.
		 if info.Mode().Perm()&0o444 == 0 {
			 continue
		 }
 
		 // Wandle den Dateinamen in den Tunnel-Namen um.
		 name, err = NameFromPath(name)
		 if err != nil {
			 continue
		 }
		 configs = append(configs, name)
	 }
	 return configs, nil
 }
 
 // LoadFromName versucht zuerst die verschlüsselte Datei zu laden,
 // und wenn diese nicht existiert, wird die unverschlüsselte Datei verwendet.
 func LoadFromName(name string) (*Config, error) {
	 configFileDir, err := tunnelConfigurationsDirectory()
	 if err != nil {
		 return nil, err
	 }
	 encryptedPath := filepath.Join(configFileDir, name+configFileSuffix)
	 if _, err := os.Stat(encryptedPath); err == nil {
		 return LoadFromPath(encryptedPath)
	 }
	 unencryptedPath := filepath.Join(configFileDir, name+configFileUnencryptedSuffix)
	 if _, err := os.Stat(unencryptedPath); err == nil {
		 return LoadFromPath(unencryptedPath)
	 }
	 return nil, errors.New("configuration file not found")
 }
 
 func LoadFromPath(path string) (*Config, error) {
	 name, err := NameFromPath(path)
	 if err != nil {
		 return nil, err
	 }
	 bytes, err := os.ReadFile(path)
	 if err != nil {
		 return nil, err
	 }
	 // Falls die Datei verschlüsselt ist, entschlüsseln.
	 if strings.HasSuffix(path, configFileSuffix) {
		 bytes, err = dpapi.Decrypt(bytes, name)
		 if err != nil {
			 return nil, err
		 }
	 }
	 return FromWgQuickWithUnknownEncoding(string(bytes), name)
 }
 
 func PathIsEncrypted(path string) bool {
	 return strings.HasSuffix(filepath.Base(path), configFileSuffix)
 }
 
 func NameFromPath(path string) (string, error) {
	 name := filepath.Base(path)
	 switch {
	 case strings.HasSuffix(name, configFileSuffix) && len(name) > len(configFileSuffix):
		 name = strings.TrimSuffix(name, configFileSuffix)
	 case strings.HasSuffix(name, configFileUnencryptedSuffix) && len(name) > len(configFileUnencryptedSuffix):
		 name = strings.TrimSuffix(name, configFileUnencryptedSuffix)
	 default:
		 return "", errors.New("Path must end in either " + configFileSuffix + " or " + configFileUnencryptedSuffix)
	 }
	 if !TunnelNameIsValid(name) {
		 return "", errors.New("Tunnel name is not valid")
	 }
	 return name, nil
 }
 
 func (config *Config) Save(overwrite bool) error {
	 if !TunnelNameIsValid(config.Name) {
		 return errors.New("Tunnel name is not valid")
	 }
	 configFileDir, err := tunnelConfigurationsDirectory()
	 if err != nil {
		 return err
	 }
	 filename := filepath.Join(configFileDir, config.Name+configFileSuffix)
	 bytes := []byte(config.ToWgQuick())
	 encryptedBytes, err := dpapi.Encrypt(bytes, config.Name)
	 if err != nil {
		 return err
	 }
	 return writeLockedDownFile(filename, overwrite, encryptedBytes)
 }
 
 func (config *Config) Path() (string, error) {
	 if !TunnelNameIsValid(config.Name) {
		 return "", errors.New("Tunnel name is not valid")
	 }
	 configFileDir, err := tunnelConfigurationsDirectory()
	 if err != nil {
		 return "", err
	 }
	 return filepath.Join(configFileDir, config.Name+configFileSuffix), nil
 }
 
 func DeleteName(name string) error {
	 if !TunnelNameIsValid(name) {
		 return errors.New("Tunnel name is not valid")
	 }
	 configFileDir, err := tunnelConfigurationsDirectory()
	 if err != nil {
		 return err
	 }
	 return os.Remove(filepath.Join(configFileDir, name+configFileSuffix))
 }
 
 func (config *Config) Delete() error {
	 return DeleteName(config.Name)
 }
 