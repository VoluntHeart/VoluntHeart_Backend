package dev.webProject.VoluntHeart.Models;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;
import org.springframework.data.mongodb.core.mapping.DocumentReference;
import dev.webProject.VoluntHeart.Models.Users.UserModel;
import lombok.Data;

@Data
@Document(collection = "posts")
public class Posts{
    
@Id
private String postId;

private String uniqueKey;
private String content;
private String image;
private String video;
private Location location;
private LocalDateTime createdAt;
private UserModel createdBy;

private List<Comment> comments = new ArrayList<>();
private List<Media> media = new ArrayList<>();

@DocumentReference
private List<LikeModel> postLikes = new ArrayList<>();







}
