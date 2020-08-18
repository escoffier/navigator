package component

import (
	"gitlab.com/piccolo_su/vegeta/pkg/redclair"
)

//func SaveImageCve(report redclair.VulnerabilityReport, digest string) error {
//	var thisImageResultCollection string
//	var thisImageResultFlattenCollection string
//	thisImageResultCollection = "image_result"
//	thisImageResultFlattenCollection = "image_flatten_result"
//	var err error
//	if len(report.Vulnerabilities) > 0 {
//		var dataFlattened []interface{}
//		var dataVulnerabilities []redclair.VulnerabilityInfo
//		for _, vulnerability := range report.Vulnerabilities {
//			targetVulnerability := TmpVulnerability(vulnerability)
//			if targetVulnerability.IsNotCommon() {
//				dataVulnerabilities = append(dataVulnerabilities, vulnerability)
//				dataFlattened = append(dataFlattened, ClairVulnerabilityFlattenedReport{
//					digest,
//					report.Image,
//					report.Hash,
//					targetVulnerability.FeatureName,
//					targetVulnerability.FeatureVersion,
//					targetVulnerability.Vulnerability,
//					targetVulnerability.Namespace,
//					targetVulnerability.Description,
//					targetVulnerability.Link,
//					targetVulnerability.Severity,
//					targetVulnerability.FixedBy,
//				})
//			}
//		}
//
//		var data = ClairVulnerabilityReport{
//			digest,
//			report.Image,
//			report.Hash,
//			report.Unapproved,
//			dataVulnerabilities,
//		}
//
//		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
//
//		_, err = dbInstance.Collection(thisImageResultCollection).InsertOne(ctx, data)
//		if err != nil {
//			// When _id exist will cause error, try to update item
//			ctx, _ = context.WithTimeout(context.Background(), 5*time.Second)
//			_, err = dbInstance.Collection(thisImageResultCollection).UpdateOne(ctx,
//				bson.M{"_id": digest}, data)
//
//			if err != nil {
//				log.Warnf("Cannot save report to database %v", err)
//				return err
//			}
//		}
//		log.Infof("Saved report %s", digest)
//
//		// DO NOT check repeated vulnerabilities, or will cause HORRIBLE timeout
//		if len(dataFlattened) > 0 {
//			_, err = dbInstance.Collection(thisImageResultFlattenCollection).InsertOne(ctx, dataFlattened)
//			if err != nil {
//				log.Warnf("Cannot save flattened report to database %v", err)
//				return err
//			}
//		}
//
//	} else {
//		log.Infof("Saved report %s (flattened) (no vulnerabilities)", digest)
//	}
//	log.Infof("Saved report %s (flattened)", digest)
//	return nil
//}
//
//func SaveImageFileSignature(
//	imageNameTag string, imageFileSignature []redclair.FileSignature, digest string) error {
//	var thisImageFileSignatureCollection string
//	thisImageFileSignatureCollection = "image_file_signature"
//	var err error
//
//	if len(imageFileSignature) > 0 {
//		var dataFlattened []interface{}
//		var dataFiltered []AggregatedTempFileSignature
//		for _, signature := range imageFileSignature {
//			var err error
//			targetFile := TempFileSignature{
//				signature.Name,
//				signature.Digest,
//				signature.Size,
//				signature.HeadContent,
//				-1,
//				nil,
//				false,
//			}
//			//if err = targetFile.VirusAnalyse(); err != nil {
//			//	log.Warn(err)
//			//}
//			if err = targetFile.SensitiveInfoAnalyse(); err != nil {
//				log.Warn(err)
//			}
//			if targetFile.IsNotCommon() {
//				dataFlattened = targetFile.DumpToDb(dataFlattened, digest)
//				dataFiltered = append(dataFiltered, targetFile.DumpToAggregatedDb())
//			}
//		}
//
//		var data = ClairImageFileSignature{
//			digest,
//			imageNameTag,
//			dataFiltered,
//		}
//
//		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
//		_, err = dbInstance.Collection(thisImageFileSignatureCollection).InsertOne(ctx, data)
//		if err != nil {
//			// When _id exist will cause error, try to update item
//			ctx, _ = context.WithTimeout(context.Background(), 5*time.Second)
//			_, err = dbInstance.Collection(thisImageFileSignatureCollection).UpdateOne(ctx,
//				bson.M{"_id": digest}, data)
//			if err != nil {
//				log.Warnf("Cannot save file signature to database %v", err)
//				return err
//			}
//		}
//		log.Infof("Saved file signature %s", digest)}
//		}
//	} else {
//		log.Infof("Saved file signature %s (flattened) (no files)", digest)
//		return nil
//	}
//	log.Infof("Saved file signature %s (flattened)", digest)
//	return nil
//}
//
//func SaveImageSoftware(
//	imageNameTag string, imageSoftware []redclair.Software, digest string) error {
//	var thisImageSoftwareCollection string
//	var thisImageSoftwareFlattenCollection string
//	thisImageSoftwareCollection = "image_software"
//	thisImageSoftwareFlattenCollection = "image_software_flatten"
//	var err error
//
//	if len(imageSoftware) > 0 {
//		var dataFlattened []interface{}
//		var dataFiltered []redclair.Software
//		dataDistinctMap := make(map[redclair.Software]struct{})
//		for _, software := range imageSoftware {
//			targetSoftware := TmpSoftware(software)
//			if _, exist := dataDistinctMap[software]; targetSoftware.IsNotCommon() && !exist {
//				dataFlattened = append(dataFlattened, ClairImageFlattenedSoftware{
//					digest,
//					targetSoftware.Name,
//					targetSoftware.Version,
//					targetSoftware.VersionFormat,
//					string(targetSoftware.Type),
//				})
//				dataFiltered = append(dataFiltered, software)
//				dataDistinctMap[software] = struct{}{} // For filter same software in different layer
//			}
//		}
//
//		var data = ClairImageSoftware{
//			digest,
//			imageNameTag,
//			dataFiltered,
//		}
//		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
//
//		_, err = dbInstance.Collection(thisImageSoftwareCollection).InsertOne(ctx, data)
//		if err != nil {
//			// When _id exist will cause error, try to update item
//			ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
//			_, err = dbInstance.Collection(thisImageSoftwareCollection).UpdateOne(ctx,
//				bson.M{"_id": digest}, data)
//			if err != nil {
//				log.Warnf("Cannot save software list to database %v", err)
//				return err
//			}
//		}
//		log.Infof("Saved software list %s", digest)
//	} else {
//		log.Infof("Saved software list %s (no vulnerabilities)", digest)
//	}
//	log.Infof("Saved software list %s", digest)
//	return nil
//}

// LoadImageCveByDigest ...
func LoadImageCveByDigest(digest string) (redclair.ClairVulnerabilityReport, error) {
	//var thisImageResultCollection string

	//thisImageResultCollection = "image_result"
	//ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	//query, _ := dbInstance.Collection(thisImageResultCollection).Find(ctx,
	//	bson.M{"digest": digest})
	report := redclair.ClairVulnerabilityReport{}

	// TODO query db and find scan report
	//err = query.All(&report)
	//if err != nil {
	//	log.Warn().Msgf("%v", err)
	//	return redclair.ClairVulnerabilityReport{}, err
	//}
	//if len(report) == 0 {
	//	return redclair.ClairVulnerabilityReport{}, ErrReportNotFound
	//}
	//if len(report) > 1 {
	//	log.Info().Msgf("Multiple report of digest [%s]", digest)
	//}
	//return report[len(report)-1], nil

	return report, nil
}

//
//func LoadImageFileSignatureByDigest(digest string) (ClairImageFileSignature, error) {
//	var err error
//	var thisImageFileSignatureCollection string
//
//	thisImageFileSignatureCollection = "image_file_signature"
//	query := dbInstance.Collection((thisImageFileSignatureCollection).FindId(digest)
//	var report []ClairImageFileSignature
//	err = query.All(&report)
//	if err != nil {
//		log.Warnf("%v", err)
//		return ClairImageFileSignature{}, err
//	}
//	if len(report) == 0 {
//		return ClairImageFileSignature{}, ErrReportNotFound
//	}
//	if len(report) > 1 {
//		log.Infof("Multiple file signature report of digest [%s]", digest)
//	}
//	return report[len(report)-1], nil
//}
//
//func LoadImageSoftwareByDigest(digest string) (ClairImageSoftware, error) {
//	var err error
//	var thisImageSoftwareCollection string
//
//	thisImageSoftwareCollection = "image_software_collection"
//	query := dbInstance.Collection((thisImageSoftwareCollection).FindId(digest)
//	var report []ClairImageSoftware
//	err = query.All(&report)
//	if err != nil {
//		log.Warnf("%v", err)
//		return ClairImageSoftware{}, err
//	}
//	if len(report) == 0 {
//		return ClairImageSoftware{}, ErrReportNotFound
//	}
//	if len(report) > 1 {
//		log.Infof("Multiple software report of digest [%s]", digest)
//	}
//	return report[len(report)-1], nil
//}
