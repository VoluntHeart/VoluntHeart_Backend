package dev.webProject.VoluntHeart.DTOmapper;

import java.util.ArrayList;
import java.util.List;
import dev.webProject.VoluntHeart.DTO.PostsDTO;
import dev.webProject.VoluntHeart.DTO.UserDTO;
import dev.webProject.VoluntHeart.Models.LikeModel;
import dev.webProject.VoluntHeart.Models.Posts;
import dev.webProject.VoluntHeart.Models.Users.UserModel;

public class PostsDTOmapper {

    public static PostsDTO mapToPostsDTO(Posts posts, UserModel reqUser) {

        PostsDTO postsDTO = new PostsDTO();

        UserDTO creator = UserDTOmapper.mapToUserDTO(posts.getCreatedBy());

        postsDTO.setPostId(posts.getPostId());
        postsDTO.setUniqueKey(posts.getUniqueKey());
        postsDTO.setContent(posts.getContent());
        postsDTO.setImage(posts.getImage());
        postsDTO.setVideo(posts.getVideo());
        postsDTO.setLocation(posts.getLocation());
        postsDTO.setCreatedAt(posts.getCreatedAt());
        postsDTO.setCreatedBy(creator);
        postsDTO.setLiked(isLikedByReqUser(posts, reqUser));
        postsDTO.setCreator(isCreatedByReqUser(creator, reqUser));
        postsDTO.setTotalLikes(posts.getPostLikes().size());
        postsDTO.setMediaList(posts.getMedia());
        postsDTO.setComments(posts.getComments());
        
        return postsDTO;
    }

    private static boolean isLikedByReqUser(Posts posts, UserModel reqUser) {

        for (LikeModel like : posts.getPostLikes()) {
            if (like.getUserId().equals(reqUser.getUserId())) {
                return true;
            }
        }
        return false;
    }

    private static boolean isCreatedByReqUser(UserDTO creator, UserModel reqUser) {
        if (creator.getUserId().equals(reqUser.getUserId())) {
            return true;
        }
        return false;
    }

    public static List<PostsDTO> toListOfPostDTOs(List<Posts> postList,UserModel user){
        List<PostsDTO> postsDTOsList = new ArrayList<>();

        for(Posts post:postList){
            PostsDTO postsDTO = mapToPostsDTO(post, user);
            postsDTOsList.add(postsDTO);
        }
        return postsDTOsList;

    }

}
