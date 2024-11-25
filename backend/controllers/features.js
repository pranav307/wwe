import { feature } from "../model/featureimage.js";



 export const addFeatureImage=async(req,res)=>{
    try {
        const {image} =req.body;
        console.log(image,"image");
        const featureImages =new feature({
            image,
        })
        await featureImages.save();
        res.status(201).json({
            success: true,
            data: featureImages,
          });

    } catch (e) {
        console.log(e);
        res.status(500).json({
          success: false,
          message: "Some error occured!",
        });
    
    }
}

export const getFeatureImages=async(req,res)=>{
    try {
        const images =await feature.find({});
        res.status(200).json({
            success: true,
            data: images,
          });
    } catch (e) {
        console.log(e);
    res.status(500).json({
      success: false,
      message: "Some error occured!",
    });
    }
}
// featureimage.js

export const deleteFeatureImage = async (req, res) => {
    try {
      const { id } = req.params;
      const deletedImage = await feature.findByIdAndDelete(id);
      
      if (!deletedImage) {
        return res.status(404).json({
          success: false,
          message: "Image not found!",
        });
      }
  
      res.status(200).json({
        success: true,
        message: "Image deleted successfully",
        data: deletedImage,
      });
    } catch (e) {
      console.log(e);
      res.status(500).json({
        success: false,
        message: "Some error occurred!",
      });
    }
  };

  
  