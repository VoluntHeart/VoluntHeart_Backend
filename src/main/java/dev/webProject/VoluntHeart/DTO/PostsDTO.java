package dev.webProject.VoluntHeart.DTO;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import dev.webProject.VoluntHeart.Models.Comment;
import dev.webProject.VoluntHeart.Models.Location;
import dev.webProject.VoluntHeart.Models.Media;
import lombok.Data;

@Data
public class PostsDTO {

    private String postId;

    private String uniqueKey;
    private String content;
    private String image;
    private String video;
    private Location location;
    private LocalDateTime createdAt;
    private UserDTO createdBy;

    private List<Media> mediaList = new ArrayList<>();
    private List<Comment> comments = new ArrayList<>();

    private int totalLikes;
    private boolean isLiked;
    private boolean isCreator;

}
