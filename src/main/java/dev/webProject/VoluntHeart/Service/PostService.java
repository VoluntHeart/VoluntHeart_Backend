package dev.webProject.VoluntHeart.Service;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import dev.webProject.VoluntHeart.DTO.PostDataDTO;
import dev.webProject.VoluntHeart.Exception.UserException;
import dev.webProject.VoluntHeart.Models.Comment;
import dev.webProject.VoluntHeart.Models.Media;
import dev.webProject.VoluntHeart.Models.Posts;
import dev.webProject.VoluntHeart.Models.Users.UserModel;
import dev.webProject.VoluntHeart.Repository.PostRepo;
import dev.webProject.VoluntHeart.Repository.UserRepo;

@Service
public class PostService {

    @Autowired
    private PostRepo postRepo;

    @Autowired
    private UserRepo userRepo;

    // create post
    public Posts createPosts(PostDataDTO payload,UserModel creator) {
        
        String[] images = payload.getImages();
        String[] videos = payload.getVideos();

        Posts post = new Posts();
        String uniqueString = UUID.randomUUID().toString();

        post.setUniqueKey(uniqueString);
        post.setContent(payload.getContent());
        post.setLocation(payload.getLocation());
        
        if (images!=null) {
            for(String url:images){
                Media media = new Media();
                media.setName(url);
                media.setUrl(url);
                media.setType("image");
                post.getMedia().add(media);
               
            }   
        }
        if (videos!=null) {
            for(String url:videos){
                Media media = new Media();
                media.setName(url);
                media.setUrl(url);
                media.setType("video");
                post.getMedia().add(media);
               
            }   
        }
      
        post.setCreatedAt(LocalDateTime.now());
        post.setCreatedBy(creator);

        creator.getPostsIds().add(post);
        postRepo.insert(post);
        userRepo.save(creator);
        return post;
    }

  
    // delete posts (only for creator)
    public void deletePost(String uniqueKey, String userSecret) throws UserException {
        Posts post = postRepo.findByUniqueKey(uniqueKey);
        UserModel creator = post.getCreatedBy();

        if (!userSecret.equals(creator.getUserSecret())) {
            throw new UserException("Permission Denied!");
        }

        postRepo.delete(post);
        creator.getPostsIds().remove(post);
    }


    public List<Posts> allPosts() {
        Sort sort = Sort.by(Sort.Direction.DESC, "createdAt");
        return postRepo.findAll(sort);
    }

    public Posts findByID(String id) {
        return postRepo.findByPostId(id);
    }

    public Posts findPostByUniqueKey(String uniqueKey){
        return postRepo.findByUniqueKey(uniqueKey);
    }

    public List<Posts> findByUser(UserModel user){
        return postRepo.findByCreatedBy(user);

    }
    // search by content
    public List<Posts> findbyContent(String keyword) {
        
        return postRepo.findByContentContainingIgnoreCase(keyword);

    }

    public Comment createComment (Comment reqComment, UserModel reqUser){

        Posts post = findPostByUniqueKey(reqComment.getPostKey());

        Comment newComment = new Comment();
        newComment.setComment(reqComment.getComment());
        newComment.setPostKey(reqComment.getPostKey());
        newComment.setUserKey(reqUser.getUserSecret());
        newComment.setUserName(reqUser.getFullName());
        newComment.setCommentAt(LocalDateTime.now());
        post.getComments().add(newComment);
        postRepo.save(post);

        return newComment;
    }


}
