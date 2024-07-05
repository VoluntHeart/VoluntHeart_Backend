package dev.webProject.VoluntHeart.Service;



import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import dev.webProject.VoluntHeart.Models.LikeModel;
import dev.webProject.VoluntHeart.Models.Posts;
import dev.webProject.VoluntHeart.Models.Users.UserModel;
import dev.webProject.VoluntHeart.Repository.LikeRepo;
import dev.webProject.VoluntHeart.Repository.PostRepo;
import dev.webProject.VoluntHeart.Repository.UserRepo;

@Service
public class LikeService {

    @Autowired
    LikeRepo likeRepo;

    @Autowired
    PostService postService;

    @Autowired
    UserService userService;

    @Autowired
    PostRepo postRepo;

    @Autowired
    UserRepo userRepo;

    // like unlike handling
    public LikeModel likeHandler(String jwt, String uniqueKey) {
       
        UserModel user = userService.findByJwtToken(jwt);
        Posts post = postService.findPostByUniqueKey(uniqueKey);
        LikeModel isLikeExist = likeRepo.findByUserIdAndLikedPostId(user.getUserId(), post.getPostId());
       
        if (isLikeExist != null) {

            user.getLikedPosts().remove(post);
            post.getPostLikes().remove(isLikeExist);
            likeRepo.delete(isLikeExist);
            postRepo.save(post);
            userRepo.save(user);
            return isLikeExist;

        }

        LikeModel like = new LikeModel();
        

        like.setLikedPostId(post.getPostId());
        like.setUserId(user.getUserId());

        post.getPostLikes().add(like);
        user.getLikedPosts().add(post);
        likeRepo.save(like);
        postRepo.save(post);
        userRepo.save(user);

        return like;
    }
}
