package dev.webProject.VoluntHeart.Models;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import lombok.Data;

@Data
@Document(collection ="like")
public class LikeModel {

    @Id
    private String likeId;
   
    private String userId;
    private String likedPostId;

}
