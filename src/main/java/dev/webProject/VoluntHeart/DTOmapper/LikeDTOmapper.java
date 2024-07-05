package dev.webProject.VoluntHeart.DTOmapper;

import dev.webProject.VoluntHeart.DTO.LikeDTO;
import dev.webProject.VoluntHeart.Models.LikeModel;


public class LikeDTOmapper {
    
    public static LikeDTO mapToLikeDTO(LikeModel like){

        LikeDTO likeDTO = new LikeDTO();
        
        likeDTO.setLikeId(like.getLikeId());
        likeDTO.setUserId(like.getUserId());;
        likeDTO.setLikedPostId(like.getLikedPostId());;


        return likeDTO;

    }
}
